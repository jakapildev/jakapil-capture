using System.Security.Cryptography;
using System.Text;

namespace Jakapil.Capture.Anonymization;

/// <summary>
/// Computes the HMAC-SHA256 correlation digest (ADR-0002 §6.2) and the deterministic synthetic-PII seed hash
/// (§7) from the customer's HMAC key. Pure/stateless given the key — no IO, no clock, no randomness.
/// </summary>
internal static class FingerprintGenerator
{
    /// <summary>128 bit — the minimum digest length the server-side <c>ValueEnvelope</c> parser requires.</summary>
    private const int DigestBytes = 16;

    /// <summary>
    /// <c>digest = HMAC-SHA256(key, tenantId \0 projectId \0 environment \0 semanticKind \0 canonicalValue)[0..16]</c>,
    /// base64url-encoded (ADR §6.2). <b><c>jsonType</c> is deliberately NOT part of the input</b> — this is
    /// INV-A1: the same business value must produce the same digest whether it was captured as a quoted JSON
    /// string, a bare JSON number, or a raw route/query token, so a cross-position correlation edge exists.
    /// <paramref name="canonicalValue"/> is the raw, un-normalized text (no numeric normalization — a
    /// leading-zero string like <c>"00123"</c> must NOT collide with <c>"123"</c>).
    /// </summary>
    public static string ComputeCorrelationDigest(
        ReadOnlySpan<byte> key, string tenantId, string projectId, string environment, string semanticKind, string canonicalValue)
    {
        var hash = HMACSHA256.HashData(key, BuildInput(tenantId, projectId, environment, semanticKind, canonicalValue));
        return Base64UrlManual.Encode(hash.AsSpan(0, DigestBytes));
    }

    /// <summary>
    /// Deterministic seed bytes for synthetic PII generation (ADR §7):
    /// <c>HMAC-SHA256(key, tenantId \0 projectId \0 environment \0 kind \0 rawValue)</c>. The same production
    /// value always maps to the same synthetic value — deliberate, so interaction dedup, noise learning
    /// (stable-after-2-observations), and request→response echo relationships all still work downstream.
    /// </summary>
    public static byte[] ComputeSyntheticSeed(
        ReadOnlySpan<byte> key, string tenantId, string projectId, string environment, string kind, string rawValue) =>
        HMACSHA256.HashData(key, BuildInput(tenantId, projectId, environment, kind, rawValue));

    /// <summary><c>\0</c>-separated, UTF-8 encoded input, per ADR §6.2.</summary>
    private static byte[] BuildInput(string a, string b, string c, string d, string e)
    {
        var sb = new StringBuilder(a.Length + b.Length + c.Length + d.Length + e.Length + 4);
        sb.Append(a).Append('\0').Append(b).Append('\0').Append(c).Append('\0').Append(d).Append('\0').Append(e);
        return Encoding.UTF8.GetBytes(sb.ToString());
    }
}
