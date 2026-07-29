namespace Jakapil.Capture.Replay;

/// <summary>
/// The parsed, still-untrusted fields of an <c>X-Jakapil-Replay</c> header (ADR-0003 §6.3). Parsing only
/// checks SHAPE (all eleven fields present, no unknown fields, well-formed <c>key=value</c> pairs) — it proves
/// nothing about authenticity; that is <c>ReplayVerifier</c>'s job. <c>Method</c>, <c>Route</c>, and
/// <c>BodyHash</c> are deliberately NOT part of this type: the header never carries them, they are always
/// recomputed from the request the SDK actually received (ADR-0003 §6.2's closing rule).
/// </summary>
internal sealed record ReplayHeader(
    string Version,
    string Alg,
    string KeyId,
    string TenantId,
    string EnvironmentId,
    string RunId,
    string RequestId,
    string Timestamp,
    string Expiry,
    string Nonce,
    string Signature)
{
    /// <summary>Parses a raw <c>X-Jakapil-Replay</c> header value into its eleven <c>;</c>-separated
    /// <c>key=value</c> fields. Returns null (never throws) on ANY shape problem: an empty/whitespace value,
    /// a pair without <c>=</c>, an unrecognized field name, or any of the eleven required fields missing —
    /// matching INV-B3 (a malformed header is simply "not a valid signature", not an error).</summary>
    public static ReplayHeader? TryParse(string? headerValue)
    {
        if (string.IsNullOrWhiteSpace(headerValue))
        {
            return null;
        }

        string? version = null, alg = null, keyId = null, tenantId = null, environmentId = null;
        string? runId = null, requestId = null, timestamp = null, expiry = null, nonce = null, signature = null;

        foreach (var part in headerValue.Split(';', StringSplitOptions.RemoveEmptyEntries))
        {
            var separatorIndex = part.IndexOf('=');
            if (separatorIndex <= 0 || separatorIndex == part.Length - 1)
            {
                return null;
            }

            var key = part[..separatorIndex];
            var value = part[(separatorIndex + 1)..];

            switch (key)
            {
                case "v": version = value; break;
                case "alg": alg = value; break;
                case "kid": keyId = value; break;
                case "tid": tenantId = value; break;
                case "eid": environmentId = value; break;
                case "rid": runId = value; break;
                case "req": requestId = value; break;
                case "ts": timestamp = value; break;
                case "exp": expiry = value; break;
                case "n": nonce = value; break;
                case "sig": signature = value; break;
                default: return null; // Unknown field: fail closed rather than silently ignore.
            }
        }

        if (version is null || alg is null || keyId is null || tenantId is null || environmentId is null ||
            runId is null || requestId is null || timestamp is null || expiry is null || nonce is null ||
            signature is null)
        {
            return null;
        }

        return new ReplayHeader(version, alg, keyId, tenantId, environmentId, runId, requestId, timestamp, expiry, nonce, signature);
    }
}
