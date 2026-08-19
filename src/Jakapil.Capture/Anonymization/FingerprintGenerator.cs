using System.Security.Cryptography;
using System.Text;

namespace Jakapil.Capture.Anonymization;

/// <summary>
/// Computes the HMAC-SHA256 correlation digest (ADR-0002 §6.2) and the deterministic synthetic-PII seed hash
/// (§7) from the customer's HMAC key. Pure/stateless given the key — no IO, no clock, no randomness.
/// </summary>
/// <remarks>
/// The domain-separation input is a single <c>scopeRef</c> — the scope-reference half of the ingest key
/// (<see cref="IngestKeyFormat"/>) — rather than three separately configured tenant/project/environment
/// strings. It identifies exactly the same thing (one environment of one project of one tenant) but is issued
/// by the server and therefore cannot be left blank. <b>Digests produced after this change differ from the
/// ones produced before it</b>, which is the intended outcome: deployments that never filled the old scope
/// strings in were all sharing a single empty domain.
/// </remarks>
internal static class FingerprintGenerator
{
    /// <summary>128 bit — the minimum digest length the server-side <c>ValueEnvelope</c> parser requires.</summary>
    private const int DigestBytes = 16;

    /// <summary>
    /// <c>digest = HMAC-SHA256(key, scopeRef \0 semanticKind \0 canonicalValue)[0..16]</c>, base64url-encoded
    /// (ADR §6.2). <b><c>jsonType</c> is deliberately NOT part of the input</b> — this is INV-A1: the same
    /// business value must produce the same digest whether it was captured as a quoted JSON string, a bare JSON
    /// number, or a raw route/query token, so a cross-position correlation edge exists.
    /// <paramref name="canonicalValue"/> is the raw, un-normalized text (no numeric normalization — a
    /// leading-zero string like <c>"00123"</c> must NOT collide with <c>"123"</c>).
    /// </summary>
    public static string ComputeCorrelationDigest(
        ReadOnlySpan<byte> key, string scopeRef, string semanticKind, string canonicalValue)
    {
        var hash = HMACSHA256.HashData(key, BuildInput(scopeRef, semanticKind, canonicalValue));
        return Base64UrlManual.Encode(hash.AsSpan(0, DigestBytes));
    }

    /// <summary>
    /// Deterministic seed bytes for synthetic PII generation (ADR §7):
    /// <c>HMAC-SHA256(key, scopeRef \0 kind \0 rawValue)</c>. The same production value always maps to the same
    /// synthetic value — deliberate, so interaction dedup, noise learning (stable-after-2-observations), and
    /// request→response echo relationships all still work downstream.
    /// </summary>
    public static byte[] ComputeSyntheticSeed(
        ReadOnlySpan<byte> key, string scopeRef, string kind, string rawValue) =>
        HMACSHA256.HashData(key, BuildInput(scopeRef, kind, rawValue));

    /// <summary><c>\0</c>-separated, UTF-8 encoded input, per ADR §6.2.</summary>
    private static byte[] BuildInput(string a, string b, string c)
    {
        var sb = new StringBuilder(a.Length + b.Length + c.Length + 2);
        sb.Append(a).Append('\0').Append(b).Append('\0').Append(c);
        return Encoding.UTF8.GetBytes(sb.ToString());
    }
}
