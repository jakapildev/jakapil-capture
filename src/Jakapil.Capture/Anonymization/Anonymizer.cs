using System.Buffers;
using System.Text;
using System.Text.Json;
using Jakapil.Capture.Contracts;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Jakapil.Capture.Anonymization;

/// <summary>
/// Anonymizes a captured interaction end-to-end — request/response body, route parameters, query parameters,
/// and allowlisted headers — before it is enqueued for export (ADR-0002, Phase 15c).
/// </summary>
public interface IAnonymizer
{
    /// <summary>Returns a transformed copy of <paramref name="interaction"/> with every classified leaf value
    /// replaced by its fingerprint/synthetic/tombstone form. When no key is configured, returns the interaction
    /// UNCHANGED (pass-through — today's plaintext behavior) and never sets <see cref="CapturedInteraction.Anon"/>.</summary>
    CapturedInteraction Anonymize(CapturedInteraction interaction);

    /// <summary>True when an anonymization key is configured — i.e. masking (both capture-time, via
    /// <see cref="Anonymize"/>, and replay-time, via <see cref="MaskReplayResponseBody"/>) is possible at all.
    /// False means pass-through/legacy mode (ADR-0002 15b-5).</summary>
    bool HasKey { get; }

    /// <summary>The anonymization scheme identifier — written into <see cref="CapturedInteraction.Anon"/> on
    /// capture, and reported in the replay masking-confirmation header (ADR-0003 INV-B1) — whenever
    /// <see cref="HasKey"/> is true.</summary>
    string Scheme { get; }

    /// <summary>The configured HMAC key version (ADR-0002 §14 / ADR-0003 §8.2) — reported alongside
    /// <see cref="Scheme"/> in both places.</summary>
    int KeyVersion { get; }

    /// <summary>
    /// ADR-0003 §5: masks a LIVE replay-response body the SAME way <see cref="Anonymize"/> masks a captured
    /// one — same key, same <see cref="AnonymizationOptions.Scope"/>, same <see cref="FieldClassifier"/>
    /// decisions — EXCEPT:
    /// <list type="bullet">
    /// <item><see cref="FieldClass.FlowFingerprint"/> leaves are left as their live plaintext value instead of
    /// an <c>fp:</c> envelope, so the Runner's scenario-chain binding (ADR-0002 §2) keeps resolving them across
    /// steps.</item>
    /// <item><b>v1.2.0 — RunCredential (ADR-0003 §5 revision, WHY #1):</b> a leaf whose field name's own
    /// semantic kind is <c>token</c>/<c>session</c>/<c>cookie</c>/<c>csrf</c>/<c>cursor</c> (see
    /// <see cref="FieldNameRules.ExtractRunCredentialKind"/>) also passes through live, for the SAME structural
    /// reason as FlowFingerprint — the Runner must chain a run-issued credential (e.g. a login response's
    /// <c>token</c>) into the next step's request. Unlike FlowFingerprint this is a NAME-based override that
    /// pre-empts whatever <see cref="FieldClass"/> the leaf would otherwise resolve to (most commonly
    /// <see cref="FieldClass.SecretTombstone"/>, since <c>token</c>/<c>cookie</c> are also
    /// <see cref="FieldNameRules.SecretFieldNames"/>) — EXCEPT when <see cref="AnonymizationOptions.FieldPolicy"/>
    /// has an explicit entry for that exact field name, which always wins (veto) and is applied instead.
    /// <c>password</c> and every other secret name outside this exact 5-word list are UNAFFECTED and stay
    /// tombstoned exactly as before.</item>
    /// <item><b>v1.2.0 — idempotency (WHY #2):</b> a value that is already in the anonymized space — a
    /// well-formed <c>fp:</c>/<c>jkp:tomb:</c> envelope (<see cref="ReplayEnvelopeRecognizer"/>), or already the
    /// exact deterministic output shape of this SDK's own <see cref="SyntheticPiiGenerator"/>
    /// (<see cref="SyntheticPiiGenerator.IsAlreadySynthetic"/>) — passes through byte-identical instead of being
    /// re-masked into a SECOND, different value. Without this, a synthetic corpus value the Runner sent and the
    /// target echoed back would re-synthesize to something else, breaking every echo-equality assertion.</item>
    /// </list>
    /// </summary>
    /// <param name="bodyBytes">The complete, untruncated live response body (UTF-8 bytes).</param>
    /// <param name="contentType">The response's <c>Content-Type</c> header value, used to decide whether the
    /// body is JSON — exactly the same sniffing rule <see cref="BodyCapture.ClassifyKind"/> applies.</param>
    /// <returns>
    /// The transformed body plus the RunCredential leaf paths that passed live (<see cref="ReplayBodyMaskingResult"/>)
    /// on success — an empty body/path list for an empty input body (trivially "masked": nothing to leak).
    /// Returns <c>null</c> when the body cannot be safely masked: no key configured (<see cref="HasKey"/> is
    /// false), the content type is not JSON, or the body failed to parse as JSON. The caller MUST NOT invent a
    /// masked-looking result in that case — it must send the live body through unmodified and omit the
    /// masking-confirmation header (fail-safe, ADR-0003 INV-B1/B3).
    /// </returns>
    ReplayBodyMaskingResult? MaskReplayResponseBody(ReadOnlyMemory<byte> bodyBytes, string? contentType);

    /// <summary>
    /// v1.2.0 — RunCredential for response HEADERS (ADR-0003 §5 revision, WHY #1): decides the live-vs-masked
    /// disposition of a single signed-replay response header. The caller (<c>JakapilCaptureMiddleware</c>) only
    /// ever invokes this for <c>Set-Cookie</c> and <c>Location</c> — the two response headers that can carry a
    /// run-issued credential (a session cookie, a newly created resource's location) the Runner needs to chain —
    /// no other header is in scope for replay masking.
    /// </summary>
    /// <param name="headerName">The header's own name (e.g. <c>"Set-Cookie"</c>), used ONLY to look up
    /// <see cref="AnonymizationOptions.FieldPolicy"/> — the veto that always wins over the default live
    /// passthrough (mirrors the JSON-leaf RunCredential veto rule above).</param>
    /// <param name="headerValue">The header's live value.</param>
    /// <returns>The header's final value plus whether it passed through live (for the masking-confirmation
    /// header's <c>liveHeaders=</c> declaration) — see <see cref="ReplayHeaderDecision"/>.</returns>
    ReplayHeaderDecision ClassifyReplayResponseHeader(string headerName, string headerValue);
}

/// <summary>The result of <see cref="IAnonymizer.MaskReplayResponseBody"/>: the masked body bytes, plus the
/// JSONPath (ADR-0003 §5 revision — see <c>JakapilCaptureMiddleware.SetMaskedHeader</c>'s grammar remarks) of
/// every leaf that passed through LIVE via the v1.2.0 RunCredential mechanism — never FlowFingerprint leaves,
/// which pass through live too but are not new/declared behavior (see <see cref="Anonymizer"/>'s remarks on why
/// the declaration is scoped to RunCredential only).</summary>
public sealed record ReplayBodyMaskingResult(byte[] Body, IReadOnlyList<string> LiveJsonPaths);

/// <summary>The result of <see cref="IAnonymizer.ClassifyReplayResponseHeader"/>.</summary>
/// <param name="Value">The header's final value — unchanged from the input when <paramref name="PassedLive"/> is
/// true; the masked replacement otherwise.</param>
/// <param name="PassedLive">True when the RunCredential default (live passthrough) applied; false when a
/// <see cref="AnonymizationOptions.FieldPolicy"/> override vetoed it and <paramref name="Value"/> is that
/// override's masked result instead.</param>
public readonly record struct ReplayHeaderDecision(string Value, bool PassedLive);

/// <inheritdoc cref="IAnonymizer"/>
/// <remarks>
/// This is the single transform seam <c>JakapilCaptureMiddleware</c> runs every captured interaction through,
/// immediately before enqueueing it — see the middleware's remarks for why this seam (rather than something
/// inside <c>BodyCapture</c>) was chosen. Because the HMAC scheme is fully deterministic, each interaction can
/// be anonymized independently of any other: the same raw value always produces the same fingerprint/synthetic
/// value regardless of which request/response it appears in, so there is no cross-interaction state to manage.
/// </remarks>
public sealed class Anonymizer : IAnonymizer
{
    /// <summary>The anonymization scheme identifier written into <see cref="CapturedInteraction.Anon"/> and
    /// exposed publicly via <see cref="Scheme"/>.</summary>
    private const string SchemeId = "hmac-sha256-v1";

    private readonly byte[]? _key;
    private readonly int _keyVersion;
    private readonly AnonymizationScope _scope;
    private readonly IReadOnlyDictionary<string, FieldClass> _fieldPolicy;
    private readonly string _emailDomain;
    private readonly string[] _anonymizedHeaderNames;

    /// <summary>DI constructor: resolves the key from the configured environment variable at construction time
    /// (once, since this is registered as a singleton) and logs a startup warning if it is unset.</summary>
    public Anonymizer(IOptions<JakapilCaptureOptions> options, ILogger<Anonymizer> logger)
        : this(ResolveKeyBytes(options.Value.Anonymization, logger), options.Value.Anonymization, options.Value.AnonymizedHeaderNames)
    {
    }

    /// <summary>Test/advanced seam: takes the resolved key bytes directly (or null for pass-through mode)
    /// rather than reading the environment, so unit tests can be deterministic and independent of the host's
    /// actual environment variables.</summary>
    internal Anonymizer(byte[]? key, AnonymizationOptions anonOptions, string[] anonymizedHeaderNames)
    {
        _key = key;
        _keyVersion = anonOptions.KeyVersion;
        _scope = anonOptions.Scope;
        _fieldPolicy = new Dictionary<string, FieldClass>(anonOptions.FieldPolicy, StringComparer.OrdinalIgnoreCase);
        _emailDomain = string.IsNullOrWhiteSpace(anonOptions.SyntheticEmailDomain) ? "example.com" : anonOptions.SyntheticEmailDomain;
        _anonymizedHeaderNames = anonymizedHeaderNames;
    }

    /// <summary>Reads the raw key from the configured environment variable. Returns null (pass-through mode)
    /// and logs a visible warning if it is unset — INV-A3 in spirit: an unconfigured key must never silently
    /// masquerade as "anonymization is on".</summary>
    private static byte[]? ResolveKeyBytes(AnonymizationOptions options, ILogger logger)
    {
        var raw = Environment.GetEnvironmentVariable(options.KeyEnvironmentVariable);
        if (string.IsNullOrEmpty(raw))
        {
            logger.LogWarning(
                "Jakapil: anonymization key is not configured (environment variable {EnvVar} is unset). " +
                "Capture is running in PASS-THROUGH mode and will send PLAINTEXT request/response data to the " +
                "collector. Set {EnvVar} before running in production.",
                options.KeyEnvironmentVariable, options.KeyEnvironmentVariable);
            return null;
        }

        return Encoding.UTF8.GetBytes(raw);
    }

    /// <inheritdoc />
    public bool HasKey => _key is not null;

    /// <inheritdoc />
    public string Scheme => SchemeId;

    /// <inheritdoc />
    public int KeyVersion => _keyVersion;

    /// <inheritdoc />
    public CapturedInteraction Anonymize(CapturedInteraction interaction)
    {
        if (_key is null)
        {
            return interaction;
        }

        // Maps an ORIGINAL route-parameter value to its transformed replacement, so RawPath/LocationHeader
        // (which embed the same value as free text inside a path, not as a separately-modeled field) can be
        // rewritten consistently with RouteParameters instead of leaking the original value a second time.
        var pathValueMap = new Dictionary<string, string>(StringComparer.Ordinal);

        var transformedRouteParams = TransformRouteParameters(interaction.Request.RouteParameters, pathValueMap);
        var transformedQuery = TransformQueryParameters(interaction.Request.QueryParameters);

        var request = interaction.Request with
        {
            RawPath = TransformPathLike(interaction.Request.RawPath, pathValueMap),
            RouteParameters = transformedRouteParams,
            QueryParameters = transformedQuery,
            QueryString = BuildQueryString(transformedQuery),
            Headers = TransformHeaders(interaction.Request.Headers),
            Body = TransformBody(interaction.Request.Body),
        };

        var response = interaction.Response with
        {
            Headers = TransformHeaders(interaction.Response.Headers),
            Body = TransformBody(interaction.Response.Body),
            LocationHeader = interaction.Response.LocationHeader is null
                ? null
                : TransformPathLike(interaction.Response.LocationHeader, pathValueMap, treatUnmatchedLastSegmentAsId: true),
        };

        return interaction with
        {
            Request = request,
            Response = response,
            Anon = new AnonymizationInfo { Scheme = SchemeId, KeyVersion = _keyVersion },
        };
    }

    private IReadOnlyList<RouteParameter> TransformRouteParameters(
        IReadOnlyList<RouteParameter> routeParameters, Dictionary<string, string> pathValueMap)
    {
        if (routeParameters.Count == 0)
        {
            return routeParameters;
        }

        var result = new List<RouteParameter>(routeParameters.Count);
        foreach (var parameter in routeParameters)
        {
            var transformed = TransformTransportValue(parameter.Name, parameter.Value);
            pathValueMap.TryAdd(parameter.Value, transformed);
            result.Add(parameter with { Value = transformed });
        }

        return result;
    }

    private IReadOnlyDictionary<string, string>? TransformQueryParameters(IReadOnlyDictionary<string, string>? queryParameters)
    {
        if (queryParameters is null || queryParameters.Count == 0)
        {
            return queryParameters;
        }

        var result = new Dictionary<string, string>(queryParameters.Count, StringComparer.OrdinalIgnoreCase);
        foreach (var (name, value) in queryParameters)
        {
            result[name] = TransformTransportValue(name, value);
        }

        return result;
    }

    /// <summary>Rebuilds the raw query string from the (already transformed) parsed query parameters, rather
    /// than leaving the original raw text untouched — otherwise the original plaintext values would still leak
    /// through <c>QueryString</c> even after <c>QueryParameters</c> was anonymized.</summary>
    private static string? BuildQueryString(IReadOnlyDictionary<string, string>? queryParameters)
    {
        if (queryParameters is null || queryParameters.Count == 0)
        {
            return null;
        }

        var sb = new StringBuilder("?");
        var first = true;
        foreach (var (name, value) in queryParameters)
        {
            if (!first)
            {
                sb.Append('&');
            }

            first = false;
            sb.Append(Uri.EscapeDataString(name)).Append('=').Append(Uri.EscapeDataString(value));
        }

        return sb.ToString();
    }

    /// <summary>
    /// Rewrites a URL path (request <c>RawPath</c> or response <c>LocationHeader</c>) segment-by-segment: any
    /// segment that exactly matches an ORIGINAL route-parameter value is replaced by its already-computed
    /// transformed value (from <paramref name="pathValueMap"/>), so the same identifier is not left leaking in
    /// plaintext just because it appears embedded in a path string rather than a separately-modeled field.
    /// </summary>
    /// <remarks>
    /// For <c>LocationHeader</c> specifically (<paramref name="treatUnmatchedLastSegmentAsId"/>), a 201
    /// response's Location commonly points at a BRAND NEW resource whose id never appeared as a request route
    /// parameter (e.g. <c>POST /api/customers</c> → <c>Location: /api/customers/{newGuid}</c>). When the last
    /// segment looks identifier-shaped and has no match in the map, it is fingerprinted under the generic "id"
    /// role — deliberately matching the same role the entity's <c>id</c> field in the response BODY would
    /// resolve to, so the two correlate (ADR §9's cross-position worked example).
    /// </remarks>
    private string TransformPathLike(string pathOrUrl, IReadOnlyDictionary<string, string> pathValueMap, bool treatUnmatchedLastSegmentAsId = false)
    {
        var queryIndex = pathOrUrl.IndexOf('?');
        var pathPart = queryIndex >= 0 ? pathOrUrl[..queryIndex] : pathOrUrl;
        var suffix = queryIndex >= 0 ? pathOrUrl[queryIndex..] : string.Empty;

        var segments = pathPart.Split('/');
        for (var i = 0; i < segments.Length; i++)
        {
            if (segments[i].Length == 0)
            {
                continue;
            }

            if (pathValueMap.TryGetValue(segments[i], out var replacement))
            {
                segments[i] = replacement;
            }
            else if (treatUnmatchedLastSegmentAsId && i == segments.Length - 1 && FieldNameRules.LooksLikeIdentifierShape(segments[i]))
            {
                segments[i] = TransformTransportValue("id", segments[i]);
            }
        }

        return string.Join('/', segments) + suffix;
    }

    /// <summary>Transforms a route/query/header value (always textual — jsonType <c>u</c>, ADR §6.1: there is
    /// no JSON container type at that transport position). v1.2.0: when the value's classification resolves to
    /// <see cref="FieldClass.SyntheticPii"/>, the raw text's numeric/boolean SHAPE (detected here, independent
    /// of classification — see <see cref="SyntheticPiiGenerator.DetectTransportShape"/>) is preserved in the
    /// replacement, so e.g. a numeric <c>PageSize</c> query value stays numeric TEXT and still parses on
    /// replay (Defect 1) instead of becoming an alphanumeric token that fails the target's model binding.</summary>
    private string TransformTransportValue(string fieldName, string rawValue)
    {
        if (string.IsNullOrEmpty(rawValue))
        {
            return rawValue;
        }

        var fieldClass = FieldClassifier.Classify(fieldName, LeafValueKind.String, rawValue, _fieldPolicy);
        var shape = SyntheticPiiGenerator.DetectTransportShape(rawValue);
        return ApplyClass(fieldClass, fieldName, "u", rawValue, shape, isReplayMasking: false).Text;
    }

    /// <summary>The final transformed text for one leaf (<see cref="Text"/>), plus whether it is still valid,
    /// unquoted JSON-number-literal text (<see cref="IsNumericLiteral"/>) — only meaningful to a JSON-body
    /// NUMBER leaf writer (<see cref="WriteNumberLeaf"/>); route/query/header/JSON-string callers only ever
    /// use <see cref="Text"/>, since those positions are written as JSON strings (or plain transport text)
    /// regardless.</summary>
    private readonly record struct ClassifiedValue(string Text, bool IsNumericLiteral)
    {
        public static ClassifiedValue Quoted(string text) => new(text, IsNumericLiteral: false);

        public static ClassifiedValue Literal(string text) => new(text, IsNumericLiteral: true);
    }

    /// <summary>Applies a resolved <see cref="FieldClass"/> to produce the final transformed value for one leaf.</summary>
    /// <param name="shape">v1.2.0 type-preservation: the shape the SyntheticPii replacement must keep — see
    /// <see cref="SyntheticValueShape"/>. Callers writing a JSON string leaf, or a route/query/header value,
    /// always pass <see cref="SyntheticValueShape.Text"/> or a transport-detected shape (never affects THEIR
    /// own JSON type, since both are written as text regardless); only <see cref="WriteNumberLeaf"/> — a JSON
    /// NUMBER leaf — passes <see cref="SyntheticValueShape.Integer"/>/<see cref="SyntheticValueShape.Decimal"/>
    /// and inspects <see cref="ClassifiedValue.IsNumericLiteral"/> on the result to decide whether to write the
    /// replacement as a raw number literal instead of a quoted string.</param>
    /// <param name="isReplayMasking">ADR-0003 §5 (+ v1.2.0 revision): true ONLY for replay-response masking
    /// (<see cref="MaskReplayResponseBody"/>'s walk) — never set for ordinary capture. Gates FOUR replay-only
    /// behaviors, checked in this order (see the remarks below and each helper's own XML doc for the full
    /// rationale of each):
    /// <list type="number">
    /// <item><b>RunCredential passthrough</b> (<see cref="TryReplayRunCredentialPassthrough"/>) — a field whose
    /// name's semantic kind is <c>token</c>/<c>session</c>/<c>cookie</c>/<c>csrf</c>/<c>cursor</c> returns its
    /// live value, PRE-EMPTING whatever <paramref name="fieldClass"/> says (most commonly SecretTombstone),
    /// unless <see cref="AnonymizationOptions.FieldPolicy"/> has an explicit entry for that field name (veto).
    /// <see cref="WriteNumberLeaf"/> runs the SAME check itself, before ever calling this method, so a numeric
    /// RunCredential leaf (e.g. an integer <c>cursor</c>) keeps its JSON number type — see that method's
    /// remarks for why this can't be done from inside here.</item>
    /// <item><b>Envelope idempotency</b> (<see cref="ReplayEnvelopeRecognizer"/>, string leaves only —
    /// <paramref name="jsonType"/> <c>s</c>/<c>g</c>) — a value that is ALREADY a well-formed
    /// <c>fp:</c>/<c>jkp:tomb:</c> envelope passes through byte-identical instead of being re-wrapped a second
    /// time or re-derived under a different field name.</item>
    /// <item><b>FlowFingerprint passthrough</b> (pre-existing, ADR-0003 §5's original decision) — inside the
    /// <see cref="FieldClass.FlowFingerprint"/> case below.</item>
    /// <item><b>SyntheticPii idempotency</b> (<see cref="SyntheticPiiGenerator.IsAlreadySynthetic"/>) — inside
    /// the <see cref="FieldClass.SyntheticPii"/> case below: a value already shaped like this SDK's own
    /// deterministic synthetic output passes through unchanged instead of being re-synthesized into a second,
    /// different value (the corpus-echo idempotency fix, v1.2.0 WHY #2).</item>
    /// </list>
    /// Only #1 (RunCredential) is recorded into <paramref name="liveJsonPaths"/> — the masking-confirmation
    /// header's <c>live=</c> declaration is scoped to the NEW, name-driven passthrough this method adds; #3
    /// (FlowFingerprint) is pre-existing, undeclared behavior, and #2/#4 are idempotency recognition, not a
    /// policy decision to publish.</param>
    /// <param name="jsonPath">The current leaf's JSONPath (root <c>$</c>-relative) — only meaningful, and only
    /// ever non-null, when <paramref name="isReplayMasking"/> is true; used solely to record a RunCredential
    /// passthrough's location into <paramref name="liveJsonPaths"/>.</param>
    /// <param name="liveJsonPaths">Accumulates every RunCredential-passthrough leaf's <paramref name="jsonPath"/>
    /// — null on the capture path (never used there).</param>
    private ClassifiedValue ApplyClass(
        FieldClass fieldClass, string? fieldName, string jsonType, string rawValue, SyntheticValueShape shape,
        bool isReplayMasking = false, string? jsonPath = null, List<string>? liveJsonPaths = null)
    {
        if (isReplayMasking)
        {
            if (TryReplayRunCredentialPassthrough(fieldName, jsonPath, liveJsonPaths))
            {
                return ClassifiedValue.Quoted(rawValue);
            }

            if (jsonType is "s" or "g" && ReplayEnvelopeRecognizer.IsAlreadyMaskedEnvelope(rawValue))
            {
                return ClassifiedValue.Quoted(rawValue);
            }
        }

        switch (fieldClass)
        {
            case FieldClass.SafeLiteral:
                return ClassifiedValue.Quoted(rawValue);

            case FieldClass.FlowFingerprint:
            {
                if (isReplayMasking)
                {
                    return ClassifiedValue.Quoted(rawValue);
                }

                var role = (fieldName is not null ? FieldNameRules.ExtractIdentifierRole(fieldName) : null) ?? "id";
                var digest = FingerprintGenerator.ComputeCorrelationDigest(
                    _key!, _scope.TenantId, _scope.ProjectId, _scope.Environment, role, rawValue);
                return ClassifiedValue.Quoted(ValueEnvelopeWriter.WriteFingerprint(jsonType, role, _keyVersion, digest));
            }

            case FieldClass.SyntheticPii:
            {
                if (isReplayMasking && SyntheticPiiGenerator.IsAlreadySynthetic(fieldName, rawValue, _emailDomain, shape))
                {
                    return ClassifiedValue.Quoted(rawValue);
                }

                var synthetic = SyntheticPiiGenerator.Generate(fieldName, rawValue, _key!, _scope, _emailDomain, shape);
                return shape is SyntheticValueShape.Integer or SyntheticValueShape.Decimal
                    ? ClassifiedValue.Literal(synthetic)
                    : ClassifiedValue.Quoted(synthetic);
            }

            case FieldClass.SecretTombstone:
            {
                var kind = fieldName is not null ? FieldNameRules.Normalize(fieldName) : string.Empty;
                if (kind.Length == 0)
                {
                    kind = "secret";
                }

                return ClassifiedValue.Quoted(ValueEnvelopeWriter.WriteTombstone(jsonType, kind));
            }

            case FieldClass.Dropped:
                // Reuses the tombstone grammar as an inert, information-free placeholder (still a valid
                // envelope server-side: `jkp:tomb:<jsonType>:dropped`). Only reachable via an explicit
                // customer FieldPolicy override — never a default classification outcome.
                return ClassifiedValue.Quoted(ValueEnvelopeWriter.WriteTombstone(jsonType, "dropped"));

            default:
                return ClassifiedValue.Quoted(rawValue);
        }
    }

    /// <summary>
    /// v1.2.0 — RunCredential (ADR-0003 §5 revision, WHY #1): true when <paramref name="fieldName"/>'s semantic
    /// kind is on the RunCredential allowlist (<see cref="FieldNameRules.ExtractRunCredentialKind"/>) and the
    /// customer has NOT explicitly overridden that exact field name via
    /// <see cref="AnonymizationOptions.FieldPolicy"/> (an explicit policy entry always wins — veto). As a side
    /// effect, records <paramref name="jsonPath"/> into <paramref name="liveJsonPaths"/> ONLY when returning
    /// true — this is what makes the returned list exactly "the leaves this call passed live", suitable to embed
    /// directly in the masking-confirmation header's <c>live=</c> declaration with no further filtering. A
    /// pattern already present is NOT added again — this is what keeps an array's shared <c>[*]</c> path
    /// (recorded once per LEAF, i.e. once per array element during the walk) reduced to a single declared entry
    /// regardless of how many elements the array actually has.
    /// </summary>
    private bool TryReplayRunCredentialPassthrough(string? fieldName, string? jsonPath, List<string>? liveJsonPaths)
    {
        if (fieldName is null || FieldNameRules.ExtractRunCredentialKind(fieldName) is null)
        {
            return false;
        }

        if (_fieldPolicy.ContainsKey(fieldName))
        {
            return false;
        }

        if (liveJsonPaths is not null)
        {
            var path = jsonPath ?? "$";
            if (!liveJsonPaths.Contains(path, StringComparer.Ordinal))
            {
                liveJsonPaths.Add(path);
            }
        }

        return true;
    }

    /// <summary>Transforms a JSON request/response body. Non-JSON bodies (form/text/binary) and empty bodies
    /// pass through unchanged — ADR-0002's field classification is defined over named JSON leaves; there is no
    /// safe, general way to anonymize an arbitrary text/binary blob without a schema.</summary>
    /// <remarks>
    /// A <see cref="CapturedBody.Truncated"/> body, or one that fails to parse as JSON, is NOT walked — its
    /// content cannot be safely classified (an incomplete document might cut a field name or value mid-token) —
    /// so its <see cref="CapturedBody.Text"/> is withheld entirely (INV-A3, fail-safe: ambiguous beats leaking
    /// plaintext) rather than being forwarded as-is.
    /// </remarks>
    private CapturedBody? TransformBody(CapturedBody? body)
    {
        if (body is null || body.Kind != BodyKind.Json || string.IsNullOrEmpty(body.Text))
        {
            return body;
        }

        if (body.Truncated)
        {
            return body with { Text = null };
        }

        try
        {
            using var document = JsonDocument.Parse(body.Text);
            var buffer = new ArrayBufferWriter<byte>(body.Text.Length);
            using (var writer = new Utf8JsonWriter(buffer))
            {
                WriteTransformed(writer, document.RootElement, null, null, isReplayMasking: false, jsonPath: "$", liveJsonPaths: null);
            }

            var newText = Encoding.UTF8.GetString(buffer.WrittenSpan);
            return body with { Text = newText, ByteSize = buffer.WrittenCount };
        }
        catch (JsonException)
        {
            return body with { Text = null };
        }
    }

    /// <inheritdoc />
    public ReplayBodyMaskingResult? MaskReplayResponseBody(ReadOnlyMemory<byte> bodyBytes, string? contentType)
    {
        if (_key is null)
        {
            return null;
        }

        if (bodyBytes.Length == 0)
        {
            return new ReplayBodyMaskingResult([], []);
        }

        if (!IsJsonContentType(contentType))
        {
            return null;
        }

        try
        {
            using var document = JsonDocument.Parse(bodyBytes);
            var buffer = new ArrayBufferWriter<byte>(bodyBytes.Length);
            var liveJsonPaths = new List<string>();
            using (var writer = new Utf8JsonWriter(buffer))
            {
                WriteTransformed(writer, document.RootElement, null, null, isReplayMasking: true, jsonPath: "$", liveJsonPaths: liveJsonPaths);
            }

            return new ReplayBodyMaskingResult(buffer.WrittenSpan.ToArray(), liveJsonPaths);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <inheritdoc />
    public ReplayHeaderDecision ClassifyReplayResponseHeader(string headerName, string headerValue)
    {
        // No key => no masking is possible at all (mirrors MaskReplayResponseBody's own guard); the header is
        // reported as "passed live" in the trivial sense that nothing touched it — the caller only invokes this
        // after body masking already succeeded, so in practice _key is never null here, but this keeps the
        // method safe to call standalone (e.g. from a unit test) without risking the `_key!` null-forgiving
        // operator inside ApplyClass's FlowFingerprint/SyntheticPii branches.
        if (_key is not null && _fieldPolicy.TryGetValue(headerName, out var overridden))
        {
            // Customer FieldPolicy veto always wins over the RunCredential default: run the SAME
            // classification pipeline TransformHeaders/TransformTransportValue already use for an allowlisted
            // header value, minus the replay-only passthroughs above ("veto" means "an explicit customer
            // decision", not "check RunCredential/idempotency again").
            var masked = ApplyClass(overridden, headerName, "u", headerValue, SyntheticValueShape.Text, isReplayMasking: false).Text;
            return new ReplayHeaderDecision(masked, PassedLive: false);
        }

        return new ReplayHeaderDecision(headerValue, PassedLive: true);
    }

    /// <summary>Same JSON-vs-not sniffing rule <see cref="BodyCapture.ClassifyKind"/> uses for a Content-Type
    /// header (a bare content-sniff of the bytes themselves is deliberately NOT done here, unlike
    /// <c>BodyCapture</c> — a live replay response always has an application-set Content-Type; guessing from
    /// bytes would risk mis-masking a body the content type says is something else).</summary>
    private static bool IsJsonContentType(string? contentType)
    {
        if (string.IsNullOrEmpty(contentType))
        {
            return false;
        }

        var mediaType = contentType.Split(';', 2)[0].Trim();
        return mediaType.Contains("json", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Recursively walks a JSON document, writing every scalar leaf through classification; objects
    /// carry the field name into their children, array items inherit their parent's field name (position never
    /// matters for classification — only the field NAME does, matching the server-side ingest guard's walk).</summary>
    /// <param name="parentFieldName">The field name of the nearest enclosing JSON OBJECT — i.e. the name
    /// <paramref name="element"/>'s own container was reached under — or null at the document root. Threaded
    /// through to <see cref="FieldClassifier.Classify"/> so a context-sensitive name like <c>name</c> can tell
    /// <c>$.customer.name</c> (person) apart from <c>$.catalogTypes[].name</c> (not a person) — see
    /// <see cref="FieldNameRules.ContextSensitiveFieldNames"/>. Only updated when recursing INTO an object's
    /// properties (using that object's own <paramref name="fieldName"/>); array recursion passes both
    /// <paramref name="fieldName"/> and <paramref name="parentFieldName"/> through unchanged, matching the
    /// existing "array items inherit their parent's field name" rule above.</param>
    /// <param name="isReplayMasking">See <see cref="ApplyClass"/>'s remarks — the single flag that switches this
    /// entire walk from ordinary capture-side transform to ADR-0003 §5 replay-response masking.</param>
    /// <param name="jsonPath">v1.2.0: this leaf/container's own JSONPath, built incrementally as the walk
    /// recurses — only meaningful when <paramref name="isReplayMasking"/> is true (the capture-path caller
    /// passes a fixed placeholder that is never read). Object recursion appends <c>.propertyName</c> (percent-
    /// encoded when the name is not a simple identifier — see <see cref="EncodeJsonPathSegment"/>); array
    /// recursion appends a single <c>[*]</c> wildcard ONCE per array (not per index/element) — matching this
    /// method's own pre-existing rule that array items inherit their parent's field name for classification:
    /// the declaration is equally position-independent, one path pattern covers every item.</param>
    /// <param name="liveJsonPaths">Accumulates every RunCredential-passthrough leaf's path — see
    /// <see cref="ApplyClass"/>'s remarks; null on the capture path.</param>
    private void WriteTransformed(
        Utf8JsonWriter writer, JsonElement element, string? fieldName, string? parentFieldName,
        bool isReplayMasking, string jsonPath, List<string>? liveJsonPaths)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                writer.WriteStartObject();
                foreach (var property in element.EnumerateObject())
                {
                    writer.WritePropertyName(property.Name);
                    var propertyPath = isReplayMasking ? AppendJsonPathProperty(jsonPath, property.Name) : jsonPath;
                    WriteTransformed(writer, property.Value, property.Name, parentFieldName: fieldName, isReplayMasking, propertyPath, liveJsonPaths);
                }

                writer.WriteEndObject();
                break;

            case JsonValueKind.Array:
            {
                writer.WriteStartArray();
                var itemPath = isReplayMasking ? jsonPath + "[*]" : jsonPath;
                foreach (var item in element.EnumerateArray())
                {
                    WriteTransformed(writer, item, fieldName, parentFieldName, isReplayMasking, itemPath, liveJsonPaths);
                }

                writer.WriteEndArray();
                break;
            }

            case JsonValueKind.String:
            {
                // A JSON STRING leaf's replacement is always written as a JSON string too (jsonType "s"/"g")
                // — its own type is already preserved trivially, regardless of what the string's CONTENT looks
                // like (a numeric-looking string like "12345" is still a JSON string, not a JSON number) — so
                // this always passes shape Text; only an actual JSON NUMBER leaf (below) needs shape detection.
                var raw = element.GetString() ?? string.Empty;
                var jsonType = Guid.TryParse(raw, out _) ? "g" : "s";
                var fieldClass = FieldClassifier.Classify(fieldName, LeafValueKind.String, raw, _fieldPolicy, parentFieldName);
                writer.WriteStringValue(ApplyClass(fieldClass, fieldName, jsonType, raw, SyntheticValueShape.Text, isReplayMasking, jsonPath, liveJsonPaths).Text);
                break;
            }

            case JsonValueKind.Number:
            {
                var raw = element.GetRawText();
                var fieldClass = FieldClassifier.Classify(fieldName, LeafValueKind.Number, raw, _fieldPolicy, parentFieldName);
                WriteNumberLeaf(writer, element, fieldClass, fieldName, raw, isReplayMasking, jsonPath, liveJsonPaths);
                break;
            }

            default:
                // true / false / null pass through unchanged.
                element.WriteTo(writer);
                break;
        }
    }

    /// <summary>v1.2.0: appends one property-access segment to a JSONPath, percent-encoding the property name
    /// when it is not a simple identifier — see <see cref="EncodeJsonPathSegment"/> for exactly which names
    /// qualify and why encoding (rather than e.g. quoting) was chosen.</summary>
    private static string AppendJsonPathProperty(string basePath, string propertyName) =>
        $"{basePath}.{EncodeJsonPathSegment(propertyName)}";

    /// <summary>
    /// v1.2.0: encodes one JSONPath property-name segment for the masking-confirmation header's <c>live=</c>
    /// declaration (see <c>JakapilCaptureMiddleware.SetMaskedHeader</c> for the full grammar). The common case —
    /// a name matching <c>^[A-Za-z_][A-Za-z0-9_]*$</c> — is written verbatim, unencoded, for readability. Any
    /// other name (containing <c>.</c>, <c>,</c>, <c>;</c>, <c>[</c>, <c>]</c>, whitespace, non-ASCII, ...) is
    /// percent-encoded via <see cref="Uri.EscapeDataString"/> — which already escapes every character that could
    /// collide with this grammar's delimiters (<c>.</c> for path segments, <c>,</c> for the list, <c>;</c> for
    /// header fields) EXCEPT <c>.</c> itself, which <see cref="Uri.EscapeDataString"/> deliberately leaves
    /// unescaped as an RFC 3986 "unreserved" character — so that one gap is closed with an explicit
    /// <c>%2E</c> substitution afterward. The result: no encoded segment can ever contain a literal
    /// <c>.</c>/<c>,</c>/<c>;</c>, so the whole header can always be split on <c>;</c> then <c>,</c> then
    /// <c>.</c>/<c>[*]</c> unambiguously, and each segment decoded independently with
    /// <see cref="Uri.UnescapeDataString"/> — a standard, widely-implemented algorithm on both sides (SDK here,
    /// Jakapil Runner in .NET too), rather than a bespoke escaping scheme.
    /// </summary>
    private static string EncodeJsonPathSegment(string name) =>
        IsSimpleJsonPathIdentifier(name) ? name : Uri.EscapeDataString(name).Replace(".", "%2E", StringComparison.Ordinal);

    private static bool IsSimpleJsonPathIdentifier(string name)
    {
        if (name.Length == 0 || !(char.IsAsciiLetter(name[0]) || name[0] == '_'))
        {
            return false;
        }

        for (var i = 1; i < name.Length; i++)
        {
            var c = name[i];
            if (!(char.IsAsciiLetterOrDigit(c) || c == '_'))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Writes a classified JSON NUMBER leaf — the single place both reported v1.2.0 type-preservation defects
    /// are fixed:
    /// </summary>
    /// <remarks>
    /// <list type="bullet">
    /// <item><b>Defect 2 (replay passthrough):</b> a <see cref="FieldClass.FlowFingerprint"/> leaf under
    /// <paramref name="isReplayMasking"/> (ADR-0003 §5) is returned completely UNTOUCHED — it is
    /// still exactly the original, valid JSON number, so it is written back with <see cref="JsonElement.WriteTo"/>
    /// exactly like <see cref="FieldClass.SafeLiteral"/>, instead of being wrapped in a JSON string.</item>
    /// <item><b>Defect 1 (numeric synthesis):</b> a <see cref="FieldClass.SyntheticPii"/> leaf gets a NUMERIC
    /// synthetic replacement (<see cref="SyntheticPiiGenerator.GenerateIntegerText"/>-equivalent, selected via
    /// <see cref="SyntheticValueShape.Integer"/>/<see cref="SyntheticValueShape.Decimal"/> based on whether the
    /// original had a fractional/exponent part), written as a raw JSON number literal rather than a string.</item>
    /// <item>A <see cref="FieldClass.FlowFingerprint"/> envelope (non-passthrough), <see cref="FieldClass.SecretTombstone"/>,
    /// and <see cref="FieldClass.Dropped"/> are unaffected — their envelope grammar is inherently textual and
    /// already records the original jsonType as its own embedded tag (<c>fp:n:...</c> / <c>jkp:tomb:n:...</c>,
    /// ADR-0002 §6.3/§8), so they are written as a JSON string exactly as before.</item>
    /// <item><b>v1.2.0 — RunCredential (ADR-0003 §5 revision):</b> checked FIRST, before even
    /// <paramref name="fieldClass"/> is consulted (see <see cref="ApplyClass"/>'s remarks for why RunCredential
    /// takes priority over every other disposition) — a numeric leaf whose field name matches the RunCredential
    /// allowlist (e.g. an integer pagination <c>cursor</c>) is written back UNTOUCHED via
    /// <see cref="JsonElement.WriteTo"/>, for the exact same "must not corrupt the JSON number type" reason as
    /// the FlowFingerprint case. This check cannot live inside <see cref="ApplyClass"/> alone because that
    /// method has no way to tell this caller "write this as a raw literal, not a quoted string" other than via
    /// <see cref="ClassifiedValue.IsNumericLiteral"/>, and using <see cref="ClassifiedValue.Literal"/> here would
    /// require re-deriving the exact original numeric text — <see cref="JsonElement.WriteTo"/> is simpler and
    /// provably exact (it re-emits the original token verbatim).</item>
    /// </list>
    /// </remarks>
    private void WriteNumberLeaf(
        Utf8JsonWriter writer, JsonElement element, FieldClass fieldClass, string? fieldName, string raw,
        bool isReplayMasking, string jsonPath, List<string>? liveJsonPaths)
    {
        if (isReplayMasking && TryReplayRunCredentialPassthrough(fieldName, jsonPath, liveJsonPaths))
        {
            element.WriteTo(writer);
            return;
        }

        if (fieldClass == FieldClass.SafeLiteral || (fieldClass == FieldClass.FlowFingerprint && isReplayMasking))
        {
            element.WriteTo(writer);
            return;
        }

        var shape = raw.IndexOfAny(['.', 'e', 'E']) >= 0 ? SyntheticValueShape.Decimal : SyntheticValueShape.Integer;
        var value = ApplyClass(fieldClass, fieldName, "n", raw, shape, isReplayMasking, jsonPath, liveJsonPaths);
        if (value.IsNumericLiteral)
        {
            writer.WriteRawValue(value.Text);
        }
        else
        {
            writer.WriteStringValue(value.Text);
        }
    }

    /// <summary>
    /// Tier-2 anonymization for headers (distinct from the existing Tier-1 <c>SensitiveHeaderNames</c> masking
    /// applied earlier in <c>HeaderMasking</c>): ONLY header names on the
    /// <see cref="JakapilCaptureOptions.AnonymizedHeaderNames"/> allowlist have their VALUE run through field
    /// classification/fingerprinting — most headers are transport metadata, not business flow identifiers, so
    /// blanket-transforming every header would be both wasteful and could corrupt values like Content-Type.
    /// Empty (default) allowlist means no header value is anonymized here — Tier-1 masking is unaffected either way.
    /// </summary>
    private IReadOnlyDictionary<string, string> TransformHeaders(IReadOnlyDictionary<string, string> headers)
    {
        if (_anonymizedHeaderNames.Length == 0)
        {
            return headers;
        }

        Dictionary<string, string>? result = null;
        foreach (var (name, value) in headers)
        {
            if (Array.Exists(_anonymizedHeaderNames, n => string.Equals(n, name, StringComparison.OrdinalIgnoreCase)))
            {
                result ??= new Dictionary<string, string>(headers, StringComparer.OrdinalIgnoreCase);
                result[name] = TransformTransportValue(name, value);
            }
        }

        return result ?? headers;
    }
}
