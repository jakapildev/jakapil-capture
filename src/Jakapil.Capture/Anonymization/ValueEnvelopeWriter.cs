namespace Jakapil.Capture.Anonymization;

/// <summary>
/// Writes the two envelope grammars the server-side <c>Jakapil.Core.DataFlow.ValueEnvelope.TryParse</c> parses:
/// <c>fp:&lt;jsonType&gt;:&lt;semanticKind&gt;:&lt;keyVersion&gt;:&lt;digest&gt;</c> (5 tokens) and
/// <c>jkp:tomb:&lt;jsonType&gt;:&lt;kind&gt;</c> (4 tokens) — ADR-0002 §6.3/§8.
/// </summary>
/// <remarks>
/// This must match that grammar byte-for-byte: a malformed envelope is REJECTED SILENTLY by the server (the
/// value degrades to an ordinary opaque string and correlation for that value simply dies — no error is ever
/// surfaced back to the SDK or the customer), so every rule <c>ValueEnvelope.TryParse</c> enforces is
/// re-enforced here at construction time. See <c>EnvelopeGrammarTests</c> for round-trip verification against
/// a parser mirroring that grammar.
/// </remarks>
internal static class ValueEnvelopeWriter
{
    /// <summary>Builds a fingerprint envelope. <paramref name="jsonType"/> must be one of
    /// <c>s</c>/<c>n</c>/<c>g</c>/<c>u</c>; <paramref name="semanticKind"/> must already be a non-empty
    /// ASCII-letter/digit-only token (see <see cref="FieldNameRules.Normalize"/>/<see cref="FieldNameRules.ExtractIdentifierRole"/>);
    /// <paramref name="keyVersion"/> must be non-negative.</summary>
    public static string WriteFingerprint(string jsonType, string semanticKind, int keyVersion, string digest) =>
        $"fp:{jsonType}:{semanticKind}:{keyVersion}:{digest}";

    /// <summary>Builds a secret tombstone envelope (no digest — INV-A2/§8: a tombstone carries zero information
    /// about the underlying value).</summary>
    public static string WriteTombstone(string jsonType, string kind) =>
        $"jkp:tomb:{jsonType}:{kind}";
}
