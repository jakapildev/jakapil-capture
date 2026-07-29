using System.Security.Cryptography;
using System.Text;
using Jakapil.Capture.Anonymization;

namespace Jakapil.Capture.Replay;

/// <summary>
/// Builds the canonical signature string ADR-0003 §6.2 defines — byte-for-byte, since the Jakapil Runner
/// builds the identical string independently to produce the signature this SDK verifies. Any drift here
/// (field order, separator, casing rule, an added/missing trailing newline) invalidates every signature.
/// </summary>
/// <remarks>
/// Do not "improve" this format. If the ADR's definition ever needs to change, the change must land in
/// <c>docs/adr/0003-kosum-yanit-maskeleme-imzali-replay.md</c> §6.2 first, and both this class and the Runner's
/// independent implementation must be updated together.
/// </remarks>
internal static class ReplayCanonicalString
{
    /// <summary>
    /// Joins the eleven ADR-0003 §6.2 fields — <see cref="ReplayProtocol.CanonicalPrefix"/>, then <c>alg</c>,
    /// <c>tenantId</c>, <c>environmentId</c>, <c>runId</c>, <c>requestId</c>, <c>method</c>, <c>route</c>,
    /// <c>bodyHash</c>, <c>timestamp</c>, <c>expiry</c>, <c>nonce</c> — with a single LF (<c>\n</c>, U+000A)
    /// between each field and NO trailing LF, and encodes the result as UTF-8. <paramref name="method"/> must
    /// already be upper-cased and <paramref name="route"/> must be the raw, still percent-encoded path+query
    /// exactly as received — callers are responsible for that, this method does no normalization of its own
    /// (normalizing here would risk silently drifting from what the signer actually signed).
    /// </summary>
    public static byte[] Build(
        string alg,
        string tenantId,
        string environmentId,
        string runId,
        string requestId,
        string method,
        string route,
        string bodyHashBase64Url,
        string timestamp,
        string expiry,
        string nonce)
    {
        var canonical = string.Join(
            '\n',
            ReplayProtocol.CanonicalPrefix,
            alg,
            tenantId,
            environmentId,
            runId,
            requestId,
            method,
            route,
            bodyHashBase64Url,
            timestamp,
            expiry,
            nonce);

        return Encoding.UTF8.GetBytes(canonical);
    }

    /// <summary>Computes <c>base64url(SHA-256(bodyBytes))</c> (unpadded) — ADR-0003 §6.2: the field is never
    /// omitted, an empty/absent request body still hashes to <c>SHA-256([])</c>'s base64url form.</summary>
    public static string ComputeBodyHash(ReadOnlySpan<byte> bodyBytes)
    {
        Span<byte> hash = stackalloc byte[32];
        SHA256.HashData(bodyBytes, hash);
        return Base64UrlManual.Encode(hash);
    }
}
