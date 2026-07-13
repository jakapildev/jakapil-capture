using Jakapil.Capture.Contracts;
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
/// </remarks>
public sealed class JakapilCaptureMiddleware
{
    private readonly RequestDelegate _next;
    private readonly JakapilCaptureOptions _options;
    private readonly ICapturedInteractionQueue _queue;
    private readonly IAuthTokenRegistry _authTokens;
    private readonly ICaptureRuntimeState _runtimeState;
    private readonly ILogger<JakapilCaptureMiddleware> _logger;

    /// <summary>Constructs the middleware from the next pipeline component, options, the capture queue, the token
    /// registry, remote runtime state, and the logger.</summary>
    public JakapilCaptureMiddleware(
        RequestDelegate next,
        IOptions<JakapilCaptureOptions> options,
        ICapturedInteractionQueue queue,
        IAuthTokenRegistry authTokens,
        ICaptureRuntimeState runtimeState,
        ILogger<JakapilCaptureMiddleware> logger)
    {
        _next = next;
        _options = options.Value;
        _queue = queue;
        _authTokens = authTokens;
        _runtimeState = runtimeState;
        _logger = logger;
    }

    /// <summary>Entry point for every request: if capture is not enabled (either locally disabled OR remotely
    /// turned off from the server) or sampling excluded this request, it passes the pipeline straight through;
    /// otherwise it executes the request with capture.</summary>
    public async Task InvokeAsync(HttpContext context)
    {
        if (!IsEffectivelyEnabled() || !ShouldSample(context))
        {
            await _next(context);
            return;
        }

        await InvokeCaptureAsync(context);
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
