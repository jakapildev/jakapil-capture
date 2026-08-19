using Jakapil.Capture.Anonymization;
using Jakapil.Capture.Contracts;
using Jakapil.Capture.Replay;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Jakapil.Capture;

/// <summary>ASP.NET Core middleware responsible for capturing request/response traffic and forwarding it (asynchronously, off the request thread) to the Jakapil collector via an in-memory queue.</summary>
/// <remarks>
/// Two hard guarantees:
///  1. The middleware never breaks the target application: every capture step is isolated with try/catch, and
///     any error degrades to "this interaction was not captured" instead of propagating.
///  2. The response the client receives is byte-for-byte identical to what the application produced — capture reads
///     a copy and never rewrites what goes over the wire.
/// <para>
/// <b>Anonymization seam (Phase 15c, ADR-0002):</b> after <see cref="CaptureBuilder.Build"/> assembles the wire
/// DTO and before it is enqueued, <see cref="_anonymizer"/> runs the ENTIRE interaction through one transform
/// (<c>IAnonymizer.Anonymize</c>). This single seam — rather than something inside <c>BodyCapture</c> or
/// <c>CaptureBuilder</c> itself — was chosen because it operates on the already-fully-built, structure-typed
/// DTO (body/route/query/headers all in their final shape), so it needs no knowledge of ASP.NET Core's request
/// pipeline at all; it is a pure DTO→DTO function, easy to unit test in isolation (see
/// <c>Jakapil.Capture.Tests.Anonymization</c>) and easy to reason about as "the one place plaintext could leak
/// past". When no anonymization key is configured, the transform is a no-op (pass-through, today's behavior).
/// </para>
/// <para>
/// <b>Signed-replay seam (Phase 15d-15, ADR-0003):</b> before any capture decision is made,
/// <see cref="_replayVerifier"/> checks whether the request carries a valid <c>X-Jakapil-Replay</c> signature
/// from the Jakapil Runner. A request with no such header (ordinary traffic — the overwhelming majority) pays
/// no cost at all and falls straight through to the existing capture logic, unchanged. A request with a VALID
/// signature takes a completely separate path (<see cref="InvokeReplayAsync"/>): capture is skipped
/// unconditionally, and the response is buffered in full and masked on the way out (same key/scope/
/// classification as capture, ADR-0003 §5) before it ever reaches the caller. A request with an INVALID or
/// malformed signature is treated EXACTLY like one with no header at all (INV-B3 — the signature is a
/// behavior switch, never an authorization gate, and doubt always resolves to "no special behavior").
/// </para>
/// </remarks>
public sealed class JakapilCaptureMiddleware
{
    private readonly RequestDelegate _next;
    private readonly JakapilCaptureOptions _options;
    private readonly ICapturedInteractionQueue _queue;
    private readonly IAuthTokenRegistry _authTokens;
    private readonly ICaptureRuntimeState _runtimeState;
    private readonly IAnonymizer _anonymizer;
    private readonly IReplayVerifier _replayVerifier;
    private readonly ILogger<JakapilCaptureMiddleware> _logger;

    /// <summary>Constructs the middleware from the next pipeline component, options, the capture queue, the token
    /// registry, remote runtime state, the anonymizer, the replay-signature verifier, and the logger.</summary>
    public JakapilCaptureMiddleware(
        RequestDelegate next,
        IOptions<JakapilCaptureOptions> options,
        ICapturedInteractionQueue queue,
        IAuthTokenRegistry authTokens,
        ICaptureRuntimeState runtimeState,
        IAnonymizer anonymizer,
        IReplayVerifier replayVerifier,
        ILogger<JakapilCaptureMiddleware> logger)
    {
        _next = next;
        _options = options.Value;
        _queue = queue;
        _authTokens = authTokens;
        _runtimeState = runtimeState;
        _anonymizer = anonymizer;
        _replayVerifier = replayVerifier;
        _logger = logger;
    }

    /// <summary>
    /// Entry point for every request. First checks for a valid signed-replay header (ADR-0003) — a request
    /// carrying one takes the dedicated <see cref="InvokeReplayAsync"/> path (capture suppressed, response
    /// masked) regardless of <see cref="JakapilCaptureOptions.Enabled"/>/sampling, since replay behavior is
    /// keyed off the signature, not the ambient capture on/off switch. Otherwise, if capture is not enabled
    /// (either locally disabled OR remotely turned off from the server) or sampling excluded this request, it
    /// passes the pipeline straight through; otherwise it executes the request with capture.
    /// </summary>
    public async Task InvokeAsync(HttpContext context)
    {
        if (await _replayVerifier.VerifyAsync(context))
        {
            await InvokeReplayAsync(context);
            return;
        }

        if (!IsEffectivelyEnabled() || !ShouldSample(context))
        {
            await _next(context);
            return;
        }

        await InvokeCaptureAsync(context);
    }

    /// <summary>
    /// Executes a request whose <c>X-Jakapil-Replay</c> signature has already verified (ADR-0003): the
    /// response is fully buffered (via <see cref="ReplayMaskingResponseStream"/>, never teed to the wire
    /// unbuffered like ordinary capture) so it can be masked before any byte reaches the caller. This request
    /// is NEVER captured/enqueued — capture suppression for signed replay traffic is unconditional
    /// (ADR-0003 §6.6, PLAN 15d-15-5), independent of sampling or the <see cref="JakapilCaptureOptions.Enabled"/>
    /// switch.
    /// </summary>
    /// <remarks>
    /// Mirrors <see cref="InvokeCaptureAsync"/>'s exception-deferral shape (see that method's remarks): if an
    /// OUTER exception-handling middleware registered BEFORE <c>UseJakapilCapture()</c> translates the
    /// exception into the real response, that write must still be visible to the masking stream, so
    /// finalization is deferred to <see cref="HttpResponse.OnCompleted"/> on the exception path exactly like
    /// the capture path defers there. Unlike capture, there is no need for the re-executed-status-code-pages
    /// path snapshot — masking only cares about the FINAL response bytes, never the route template.
    /// </remarks>
    private async Task InvokeReplayAsync(HttpContext context)
    {
        var originalResponseBody = context.Response.Body;
        var maskingStream = new ReplayMaskingResponseStream(_options.Replay.MaxMaskedResponseBytes);
        context.Response.Body = maskingStream;

        var deferredToCompletion = false;
        try
        {
            await _next(context);
        }
        catch
        {
            deferredToCompletion = TryDeferReplayFinalizeToCompletion(context, maskingStream, originalResponseBody);
            throw;
        }
        finally
        {
            if (!deferredToCompletion)
            {
                context.Response.Body = originalResponseBody;
                await FinalizeReplayResponseAsync(context, maskingStream, originalResponseBody);
                await maskingStream.DisposeAsync();
            }
        }
    }

    /// <summary>Registers an <see cref="HttpResponse.OnCompleted"/> callback that finalizes the replay
    /// masking once the response is fully produced — the only moment an outer exception-handler middleware's
    /// real status + error body is visible. Mirrors <see cref="TryDeferFinalizeToCompletion"/>; see that
    /// method's remarks for why this pattern is needed at all.</summary>
    private bool TryDeferReplayFinalizeToCompletion(HttpContext context, ReplayMaskingResponseStream maskingStream, Stream originalResponseBody)
    {
        try
        {
            context.Response.OnCompleted(async () =>
            {
                try
                {
                    context.Response.Body = originalResponseBody;
                    await FinalizeReplayResponseAsync(context, maskingStream, originalResponseBody);
                }
                finally
                {
                    await maskingStream.DisposeAsync();
                }
            });
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Jakapil: could not defer exception-path replay masking to OnCompleted; response will be sent unmasked");
            return false;
        }
    }

    /// <summary>
    /// Decides whether the buffered replay response can be masked, writes the (masked or, if unmaskable,
    /// original) bytes to the real response stream, and — only when masking actually ran — sets the
    /// masking-confirmation header the Jakapil cloud side requires before persisting anything (ADR-0003
    /// INV-B1). Never throws: any failure here falls back to forwarding the buffered bytes as-is, because the
    /// alternative (giving the caller nothing) would be a worse failure than an unmasked or malformed response.
    /// </summary>
    private async Task FinalizeReplayResponseAsync(HttpContext context, ReplayMaskingResponseStream maskingStream, Stream originalResponseBody)
    {
        try
        {
            var buffered = maskingStream.BufferedBytes;
            var outputBytes = buffered;
            var maskingApplied = false;
            IReadOnlyList<string>? liveJsonPaths = null;

            if (maskingStream.Truncated)
            {
                _logger.LogDebug(
                    "Jakapil: replay response ({TotalBytes} bytes) exceeded Replay.MaxMaskedResponseBytes; sending the buffered prefix through UNMASKED and without the masking-confirmation header",
                    maskingStream.TotalBytesWritten);
            }
            else if (_anonymizer.HasKey && buffered.Length > 0 && !_anonymizer.IsReplayResponseBodyJson(context.Response.ContentType))
            {
                // buffered.Length > 0 guard: an EMPTY body is trivially "masked" regardless of Content-Type
                // (MaskReplayResponseBody's own bodyBytes.Length == 0 early return, below) — there is nothing
                // in it that could leak, so it must fall through to the ordinary masked-JSON branch instead of
                // this one, and get the plain (no body= field) confirmation header, exactly like before this
                // change (e.g. a 400 with no response body at all).
                //
                // ADR-0003 §5 revision, "non-JSON pass-through": the response's Content-Type is not JSON, so
                // there is no safe, general way to mask it (same reasoning as capture-time
                // Anonymizer.TransformBody's own non-JSON pass-through — ADR-0002's field classification is
                // defined over named JSON leaves, not arbitrary text/binary blobs). Sending this body through
                // unmasked while staying SILENT (no header) would be indistinguishable, to the Jakapil cloud
                // side, from "masking was never attempted" — so instead of the pre-1.2.0 fail-closed behavior
                // (no header at all), this branch sends the confirmation header WITH an explicit
                // body=unmasked-nonjson declaration: the response IS forwarded live, and that fact is honestly
                // reported rather than hidden. Turning this body into an opaque masked blob instead — the only
                // alternative — would put capture-time (raw) and replay-time (masked) representations of the
                // same non-JSON body in different spaces, breaking every assertion built on it and
                // reintroducing exactly the false-regression problem ADR-0003 exists to prevent.
                //
                // Set-Cookie/Location RunCredential handling runs here too, same as the masked-JSON path below
                // — it inspects HEADERS, not the body, so it is independent of whether the body itself could be
                // masked; a non-JSON body must not lose that protection just because its body can't be masked.
                var liveHeaderNames = ProcessRunCredentialResponseHeaders(context);
                SetMaskedHeader(context, _anonymizer.Scheme, liveJsonPaths: null, liveHeaderNames, bodyDisposition: ReplayProtocol.UnmaskedNonJsonBodyDisposition);
                await WriteReplayResponseAsync(context, originalResponseBody, buffered, setContentLength: false);
                return;
            }
            else if (_anonymizer.HasKey)
            {
                var masked = _anonymizer.MaskReplayResponseBody(buffered, context.Response.ContentType);
                if (masked is not null)
                {
                    outputBytes = masked.Body;
                    liveJsonPaths = masked.LiveJsonPaths;
                    maskingApplied = true;
                }

                // else: content-type claimed JSON (we already ruled out non-JSON content-type above) but the
                // body still failed to parse (Anonymizer.MaskReplayResponseBody's own catch (JsonException)) —
                // this is UNAMBIGUOUSLY the malformed-JSON case, distinct from the non-JSON-content-type case
                // handled above. Fail-closed, same as before this change: maskingApplied stays false, no
                // header is sent, and the live (unparseable) body is forwarded unchanged below — its content
                // could not be classified at all, so it is treated like the Truncated case, not like the
                // deliberate non-JSON pass-through case.
            }
            else
            {
                // ADR-0003 §8.4: no anonymization key configured (legacy pass-through mode) — capture
                // suppression still applies (already unconditional, InvokeReplayAsync never captures), but
                // there is no key to mask WITH, so the live body goes through unchanged. The confirmation
                // header is still sent, with scheme=none, so the cloud side's INV-B1 guard can tell "verified
                // signature, no masking possible" apart from "no SDK / signature never verified" — both leave
                // the header off in every OTHER unmaskable case above/below, but this one is a deliberate,
                // honestly-reported exception per the ADR.
                SetMaskedHeader(context, scheme: "none");
                await WriteReplayResponseAsync(context, originalResponseBody, buffered, setContentLength: false);
                return;
            }

            // Headers (including the masking-confirmation header) MUST be set before the first byte reaches
            // the real stream — writing starts the response, after which ASP.NET Core's HttpResponse.HasStarted
            // makes further header mutation throw. WriteReplayResponseAsync is what performs that first write.
            if (maskingApplied)
            {
                // v1.2.0 — RunCredential for response headers (ADR-0003 §5 revision, WHY #1): decide the
                // Set-Cookie/Location disposition BEFORE the confirmation header, so their outcome can be
                // folded into the SAME header's liveHeaders= declaration in one write.
                var liveHeaderNames = ProcessRunCredentialResponseHeaders(context);
                SetMaskedHeader(context, _anonymizer.Scheme, liveJsonPaths, liveHeaderNames);
            }

            var contentLengthChanged = outputBytes.Length != buffered.Length;
            await WriteReplayResponseAsync(context, originalResponseBody, outputBytes, setContentLength: contentLengthChanged);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Jakapil: failed to finalize replay response masking; forwarding the buffered response unmodified");
            try
            {
                await originalResponseBody.WriteAsync(maskingStream.BufferedBytes);
                await originalResponseBody.FlushAsync();
            }
            catch (Exception writeEx)
            {
                _logger.LogDebug(writeEx, "Jakapil: failed to forward the buffered replay response after a masking error");
            }
        }
    }

    /// <summary>Writes the final response bytes to the real stream, correcting <c>Content-Length</c> first if
    /// it was explicitly set and the byte count changed (masking can change body length) — done BEFORE the
    /// first write, since nothing has touched the real stream yet at this point and the header is still
    /// mutable. If the response has unexpectedly already started (an application called
    /// <see cref="HttpResponse.StartAsync"/> itself, or similar), setting headers throws; that is swallowed so
    /// the body write below still happens rather than losing the response entirely.</summary>
    private static async Task WriteReplayResponseAsync(HttpContext context, Stream originalResponseBody, ReadOnlyMemory<byte> bytes, bool setContentLength)
    {
        if (setContentLength && !context.Response.HasStarted)
        {
            try
            {
                context.Response.ContentLength = bytes.Length;
            }
            catch (InvalidOperationException)
            {
                // Headers already sent somehow; fall through and write the body anyway.
            }
        }

        await originalResponseBody.WriteAsync(bytes);
        await originalResponseBody.FlushAsync();
    }

    /// <summary>
    /// Sets the ADR-0003 masking-confirmation header. Swallows the (rare) case where headers have already
    /// started, for the same reason as <see cref="WriteReplayResponseAsync"/>.
    /// </summary>
    /// <remarks>
    /// <para><b>Grammar (v1.2.0 — authoritative; additive over the pre-v1.2.0 <c>v1;scheme=...;keyVersion=...</c>
    /// format, which is still exactly its own prefix):</b></para>
    /// <code>
    /// X-Jakapil-Masked: v1;scheme=&lt;scheme&gt;;keyVersion=&lt;n&gt;[;body=unmasked-nonjson][;live=&lt;path&gt;(,&lt;path&gt;)*][;liveHeaders=&lt;name&gt;(,&lt;name&gt;)*]
    /// </code>
    /// <list type="bullet">
    /// <item><c>scheme</c>/<c>keyVersion</c>: unchanged from before v1.2.0.</item>
    /// <item><c>body=</c> (ADR-0003 §5 revision, "non-JSON pass-through"; positioned right after
    /// <c>keyVersion=</c>, before <c>live=</c>/<c>liveHeaders=</c>, per the protocol contract): OMITTED on the
    /// JSON-masked path — the only value this SDK version ever emits is
    /// <see cref="Jakapil.Capture.Replay.ReplayProtocol.UnmaskedNonJsonBodyDisposition"/>
    /// (<c>"unmasked-nonjson"</c>), sent when the response body's <c>Content-Type</c> was not JSON and so was
    /// forwarded byte-for-byte unmasked (mirrors <c>Anonymizer.TransformBody</c>'s capture-time non-JSON
    /// pass-through — there is no safe, general way to anonymize an arbitrary text/binary blob without a
    /// schema). The field is deliberately OMITTED rather than always emitted with an explicit
    /// <c>body=masked</c> counterpart on the JSON path: that keeps the header byte-for-byte identical, for
    /// every case that already worked, to what it was before this field existed, and matches the receiver's
    /// documented default — <b>absent <c>body=</c> means masked</b> — which is exactly what keeps every
    /// pre-1.2.0-and-this-change receiver working unchanged against a masked JSON response.</item>
    /// <item><c>live=</c> (OMITTED entirely when there are no RunCredential leaves — never an empty
    /// <c>live=</c>): a comma-separated list of JSONPaths, root-relative (<c>$</c>), of every response-body leaf
    /// that passed through LIVE via the v1.2.0 RunCredential mechanism (<see cref="IAnonymizer.MaskReplayResponseBody"/>'s
    /// <c>ReplayBodyMaskingResult.LiveJsonPaths</c>) — <see cref="FieldClass.FlowFingerprint"/> passthrough
    /// leaves (ADR-0003 §5's ORIGINAL decision, unchanged) are DELIBERATELY NOT included here: that mechanism
    /// already worked before this header existed and needs no new signal; `live=` is scoped to exactly the NEW
    /// passthrough category this version adds. Object property access is <c>.name</c>; an array is a SINGLE
    /// <c>[*]</c> wildcard covering every element (not one entry per index — matches how this SDK already
    /// classifies every array item under one shared field name, ADR-0002 §5). A property name that is not a
    /// simple <c>[A-Za-z_][A-Za-z0-9_]*</c> identifier is percent-encoded (<see cref="Uri.EscapeDataString"/>,
    /// plus an explicit <c>.</c> → <c>%2E</c> substitution for the one delimiter that function leaves unescaped)
    /// — decode with the matching <see cref="Uri.UnescapeDataString"/>. Examples: a top-level
    /// <c>{"token":"..."}</c> → <c>live=$.token</c>; <c>{"auth":{"sessionToken":"..."}}</c> →
    /// <c>live=$.auth.sessionToken</c>; <c>{"items":[{"cursor":"..."}]}</c> → <c>live=$.items[*].cursor</c>;
    /// multiple leaves are comma-joined: <c>live=$.token,$.items[*].cursor</c>.</item>
    /// <item><c>liveHeaders=</c> (also omitted when empty): a comma-separated list of response HEADER NAMES
    /// (never percent-encoded — an HTTP header name is already restricted to RFC 7230 token characters, which
    /// cannot contain <c>,</c>/<c>;</c>) that passed through live — only ever <c>Set-Cookie</c> and/or
    /// <c>Location</c>, the two headers <see cref="ProcessRunCredentialResponseHeaders"/> evaluates.</item>
    /// </list>
    /// <para><b>Parsing note for the Jakapil side:</b> split the whole value on <c>;</c> first; each resulting
    /// token is either a bare flag or a <c>key=value</c> pair. For <c>live</c>/<c>liveHeaders</c>, split their
    /// value on <c>,</c> (safe — no encoded segment can ever contain a literal comma, by construction above),
    /// then for <c>live</c> entries, split each JSONPath on <c>.</c> and <c>[*]</c> and
    /// <see cref="Uri.UnescapeDataString"/> each property segment.</para>
    /// </remarks>
    private void SetMaskedHeader(
        HttpContext context,
        string scheme,
        IReadOnlyList<string>? liveJsonPaths = null,
        IReadOnlyList<string>? liveHeaderNames = null,
        string? bodyDisposition = null)
    {
        if (context.Response.HasStarted)
        {
            return;
        }

        try
        {
            var value = $"v1;scheme={scheme};keyVersion={_anonymizer.KeyVersion}";
            if (bodyDisposition is not null)
            {
                value += $";body={bodyDisposition}";
            }

            if (liveJsonPaths is { Count: > 0 })
            {
                value += $";live={string.Join(',', liveJsonPaths)}";
            }

            if (liveHeaderNames is { Count: > 0 })
            {
                value += $";liveHeaders={string.Join(',', liveHeaderNames)}";
            }

            context.Response.Headers[ReplayProtocol.MaskedResponseHeaderName] = value;
        }
        catch (InvalidOperationException)
        {
        }
    }

    /// <summary>
    /// v1.2.0 — RunCredential for response headers (ADR-0003 §5 revision, WHY #1): applies
    /// <see cref="IAnonymizer.ClassifyReplayResponseHeader"/> to the two headers ever in scope for replay
    /// masking — <c>Set-Cookie</c> (which ASP.NET Core may repeat as multiple header lines — each is classified
    /// independently) and <c>Location</c> — replacing each present header's value(s) in place, and returns the
    /// subset of those two names that passed through live for <see cref="SetMaskedHeader"/>'s <c>liveHeaders=</c>
    /// declaration. A header that is absent from the response is skipped entirely (nothing to declare). Must run
    /// BEFORE the first response byte is written — same <see cref="HttpResponse.HasStarted"/> constraint as
    /// <see cref="SetMaskedHeader"/>, enforced the same way (swallow and skip rather than throw).
    /// </summary>
    private List<string> ProcessRunCredentialResponseHeaders(HttpContext context)
    {
        var liveHeaderNames = new List<string>();
        ProcessRunCredentialResponseHeader(context, "Set-Cookie", liveHeaderNames);
        ProcessRunCredentialResponseHeader(context, "Location", liveHeaderNames);
        return liveHeaderNames;
    }

    private void ProcessRunCredentialResponseHeader(HttpContext context, string headerName, List<string> liveHeaderNames)
    {
        if (context.Response.HasStarted || !context.Response.Headers.TryGetValue(headerName, out var values) || values.Count == 0)
        {
            return;
        }

        var results = new string[values.Count];
        var anyLive = false;
        for (var i = 0; i < values.Count; i++)
        {
            var decision = _anonymizer.ClassifyReplayResponseHeader(headerName, values[i] ?? string.Empty);
            results[i] = decision.Value;
            anyLive |= decision.PassedLive;
        }

        try
        {
            context.Response.Headers[headerName] = results;
        }
        catch (InvalidOperationException)
        {
            return;
        }

        if (anyLive)
        {
            liveHeaderNames.Add(headerName);
        }
    }

    /// <summary>Effective capture state: the local <see cref="JakapilCaptureOptions.Enabled"/> is a HARD FLOOR
    /// (if false, it can never be turned on remotely); capture is enabled only when both are true.</summary>
    private bool IsEffectivelyEnabled() => _options.Enabled && _runtimeState.Enabled;

    /// <summary>Executes a request with capture: buffers the request body, tees the response body through a pass-through wrapper, then finalizes and enqueues the interaction.</summary>
    /// <remarks>
    /// Because the response can be re-executed by status-code-pages, the original request path is snapshotted into
    /// <see cref="HttpContext.Items"/> inside an <c>OnStarting</c> callback (the only moment the feature is still present).
    /// Since an exception-handler middleware registered BEFORE <c>UseJakapilCapture()</c> writes the real status +
    /// error body only after this middleware has unwound, finalization on the exception path is deferred to
    /// <c>Response.OnCompleted</c> so that the final error body is captured as well. The exception is rethrown
    /// unchanged; the target application's own exception handling runs exactly as before.
    /// </remarks>
    private async Task InvokeCaptureAsync(HttpContext context)
    {
        var requestStart = DateTimeOffset.UtcNow;
        var startedAt = System.Diagnostics.Stopwatch.GetTimestamp();

        var requestBody = await TryCaptureRequestBodyAsync(context);

        context.Response.OnStarting(static state =>
        {
            var httpContext = (HttpContext)state!;
            var reExec = httpContext.Features.Get<IStatusCodeReExecuteFeature>();
            if (reExec?.OriginalPath is { Length: > 0 } originalPath &&
                !httpContext.Items.ContainsKey(CaptureBuilder.ReExecutedOriginalPathItemKey))
            {
                httpContext.Items[CaptureBuilder.ReExecutedOriginalPathItemKey] = originalPath;
            }

            return Task.CompletedTask;
        }, context);

        var originalResponseBody = context.Response.Body;
        var captureStream = new CapturingResponseStream(
            originalResponseBody, context.Response, _options.MaxCapturedResponseBytes, _options.StreamingContentTypes);
        context.Response.Body = captureStream;

        var deferredToCompletion = false;
        Exception? thrown = null;
        try
        {
            await _next(context);
        }
        catch (Exception ex)
        {
            thrown = ex;

            deferredToCompletion = TryDeferFinalizeToCompletion(
                context, requestStart, startedAt, requestBody, captureStream, originalResponseBody, thrown);

            throw;
        }
        finally
        {
            if (!deferredToCompletion)
            {
                var durationMs = (long)System.Diagnostics.Stopwatch.GetElapsedTime(startedAt).TotalMilliseconds;

                context.Response.Body = originalResponseBody;
                await TryFinalizeCaptureAsync(context, requestStart, durationMs, requestBody, captureStream, thrown);
                await captureStream.DisposeAsync();
            }
        }
    }

    /// <summary>Registers an <see cref="HttpResponse.OnCompleted"/> callback that finalizes capture once the response is fully produced — the only moment an outer exception-handler middleware's real status + error body is visible.</summary>
    /// <remarks>
    /// Returns true if the callback was registered (the caller then leaves the capture stream attached and
    /// not disposed for it to handle); returns false if registration fails (the caller falls back to synchronous
    /// finalization).
    /// </remarks>
    private bool TryDeferFinalizeToCompletion(
        HttpContext context,
        DateTimeOffset requestStart,
        long startedAt,
        CapturedBody? requestBody,
        CapturingResponseStream captureStream,
        Stream originalResponseBody,
        Exception thrown)
    {
        try
        {
            context.Response.OnCompleted(async () =>
            {
                try
                {
                    var durationMs = (long)System.Diagnostics.Stopwatch.GetElapsedTime(startedAt).TotalMilliseconds;
                    context.Response.Body = originalResponseBody;
                    await TryFinalizeCaptureAsync(context, requestStart, durationMs, requestBody, captureStream, thrown);
                }
                finally
                {
                    await captureStream.DisposeAsync();
                }
            });
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Jakapil: could not defer exception-path capture to OnCompleted; capturing synchronously");
            return false;
        }
    }

    /// <summary>Decides whether this request should be captured: requests carrying the <c>X-Jakapil-Synthetic</c>
    /// header (the runner's own traffic) are never captured; otherwise it is selected probabilistically according to
    /// the configured sample rate.</summary>
    private bool ShouldSample(HttpContext context)
    {
        if (context.Request.Headers.ContainsKey("X-Jakapil-Synthetic"))
        {
            return false;
        }

        if (_options.SampleRate >= 1.0)
        {
            return true;
        }

        if (_options.SampleRate <= 0.0)
        {
            return false;
        }

        return Random.Shared.NextDouble() < _options.SampleRate;
    }

    /// <summary>Buffers the request body for capture, then rewinds the body stream so that model binding and the next
    /// middleware can still read it. If buffering fails, the interaction is captured without a body.</summary>
    private async Task<CapturedBody?> TryCaptureRequestBodyAsync(HttpContext context)
    {
        try
        {
            var request = context.Request;
            request.EnableBuffering();

            using var buffer = new MemoryStream();
            await request.Body.CopyToAsync(buffer);
            request.Body.Position = 0;

            return BodyCapture.Capture(buffer.GetBuffer().AsSpan(0, (int)buffer.Length), request.ContentType, _options.MaxInlineBodyBytes);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Jakapil: failed to buffer request body; interaction will be captured without it");
            return null;
        }
    }

    /// <summary>Builds the captured response body, constructs the full interaction (<see cref="CaptureBuilder.Build"/>),
    /// and enqueues it; if the queue is full the interaction is dropped. Any error leaves the request unaffected.</summary>
    private async Task TryFinalizeCaptureAsync(
        HttpContext context,
        DateTimeOffset requestStart,
        long durationMs,
        CapturedBody? requestBody,
        CapturingResponseStream captureStream,
        Exception? thrown)
    {
        try
        {
            var responseBody = BuildResponseBody(context, captureStream);

            var interaction = CaptureBuilder.Build(context, requestStart, durationMs, requestBody, responseBody, thrown, _options, _authTokens);
            interaction = _anonymizer.Anonymize(interaction);

            if (!await TryEnqueueAsync(interaction))
            {
                _logger.LogDebug("Jakapil: capture queue full, dropped interaction {InteractionId}", interaction.Id);
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Jakapil: failed to finalize captured interaction; request was not affected");
        }
    }

    /// <summary>Builds the final <see cref="CapturedBody"/> from the capture stream.</summary>
    /// <remarks>
    /// Streaming responses are recorded with metadata only: the body is not buffered, and "not captured" is made
    /// visible via the size and the <c>Truncated</c> flag. Even when inline resolution itself did not truncate, the
    /// real response size and the limit-exceeded flag are preserved.
    /// </remarks>
    private CapturedBody? BuildResponseBody(HttpContext context, CapturingResponseStream captureStream)
    {
        if (captureStream.MetadataOnly)
        {
            return captureStream.TotalBytesWritten == 0
                ? null
                : new CapturedBody { Text = null, ByteSize = captureStream.TotalBytesWritten, Truncated = true, Kind = BodyKind.Binary };
        }

        var captured = BodyCapture.Capture(captureStream.CapturedBytes, context.Response.ContentType, _options.MaxInlineBodyBytes);
        if (captured is null)
        {
            return null;
        }

        return captureStream.Truncated
            ? captured with { Truncated = true, ByteSize = captureStream.TotalBytesWritten }
            : captured;
    }

    /// <summary>Attempts to enqueue the interaction; returns false on failure, leaving the request unaffected.</summary>
    private async Task<bool> TryEnqueueAsync(CapturedInteraction interaction)
    {
        try
        {
            await _queue.EnqueueAsync(interaction);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Jakapil: failed to enqueue captured interaction {InteractionId}", interaction.Id);
            return false;
        }
    }
}
