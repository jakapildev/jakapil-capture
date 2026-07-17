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
}

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
    /// <summary>The anonymization scheme identifier written into <see cref="CapturedInteraction.Anon"/>.</summary>
    private const string Scheme = "hmac-sha256-v1";

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
            Anon = new AnonymizationInfo { Scheme = Scheme, KeyVersion = _keyVersion },
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
    /// no JSON container type at that transport position).</summary>
    private string TransformTransportValue(string fieldName, string rawValue)
    {
        if (string.IsNullOrEmpty(rawValue))
        {
            return rawValue;
        }

        var fieldClass = FieldClassifier.Classify(fieldName, LeafValueKind.String, rawValue, _fieldPolicy);
        return ApplyClass(fieldClass, fieldName, "u", rawValue);
    }

    /// <summary>Applies a resolved <see cref="FieldClass"/> to produce the final transformed string for one leaf.</summary>
    private string ApplyClass(FieldClass fieldClass, string? fieldName, string jsonType, string rawValue)
    {
        switch (fieldClass)
        {
            case FieldClass.SafeLiteral:
                return rawValue;

            case FieldClass.FlowFingerprint:
            {
                var role = (fieldName is not null ? FieldNameRules.ExtractIdentifierRole(fieldName) : null) ?? "id";
                var digest = FingerprintGenerator.ComputeCorrelationDigest(
                    _key!, _scope.TenantId, _scope.ProjectId, _scope.Environment, role, rawValue);
                return ValueEnvelopeWriter.WriteFingerprint(jsonType, role, _keyVersion, digest);
            }

            case FieldClass.SyntheticPii:
                return SyntheticPiiGenerator.Generate(fieldName, rawValue, _key!, _scope, _emailDomain);

            case FieldClass.SecretTombstone:
            {
                var kind = fieldName is not null ? FieldNameRules.Normalize(fieldName) : string.Empty;
                if (kind.Length == 0)
                {
                    kind = "secret";
                }

                return ValueEnvelopeWriter.WriteTombstone(jsonType, kind);
            }

            case FieldClass.Dropped:
                // Reuses the tombstone grammar as an inert, information-free placeholder (still a valid
                // envelope server-side: `jkp:tomb:<jsonType>:dropped`). Only reachable via an explicit
                // customer FieldPolicy override — never a default classification outcome.
                return ValueEnvelopeWriter.WriteTombstone(jsonType, "dropped");

            default:
                return rawValue;
        }
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
                WriteTransformed(writer, document.RootElement, null);
            }

            var newText = Encoding.UTF8.GetString(buffer.WrittenSpan);
            return body with { Text = newText, ByteSize = buffer.WrittenCount };
        }
        catch (JsonException)
        {
            return body with { Text = null };
        }
    }

    /// <summary>Recursively walks a JSON document, writing every scalar leaf through classification; objects
    /// carry the field name into their children, array items inherit their parent's field name (position never
    /// matters for classification — only the field NAME does, matching the server-side ingest guard's walk).</summary>
    private void WriteTransformed(Utf8JsonWriter writer, JsonElement element, string? fieldName)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                writer.WriteStartObject();
                foreach (var property in element.EnumerateObject())
                {
                    writer.WritePropertyName(property.Name);
                    WriteTransformed(writer, property.Value, property.Name);
                }

                writer.WriteEndObject();
                break;

            case JsonValueKind.Array:
                writer.WriteStartArray();
                foreach (var item in element.EnumerateArray())
                {
                    WriteTransformed(writer, item, fieldName);
                }

                writer.WriteEndArray();
                break;

            case JsonValueKind.String:
            {
                var raw = element.GetString() ?? string.Empty;
                var jsonType = Guid.TryParse(raw, out _) ? "g" : "s";
                var fieldClass = FieldClassifier.Classify(fieldName, LeafValueKind.String, raw, _fieldPolicy);
                writer.WriteStringValue(ApplyClass(fieldClass, fieldName, jsonType, raw));
                break;
            }

            case JsonValueKind.Number:
            {
                var raw = element.GetRawText();
                var fieldClass = FieldClassifier.Classify(fieldName, LeafValueKind.Number, raw, _fieldPolicy);
                if (fieldClass == FieldClass.SafeLiteral)
                {
                    element.WriteTo(writer);
                }
                else
                {
                    writer.WriteStringValue(ApplyClass(fieldClass, fieldName, "n", raw));
                }

                break;
            }

            default:
                // true / false / null pass through unchanged.
                element.WriteTo(writer);
                break;
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
