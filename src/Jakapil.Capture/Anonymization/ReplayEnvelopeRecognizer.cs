namespace Jakapil.Capture.Anonymization;

/// <summary>
/// v1.2.0 (idempotent replay masking, WHY #2): recognizes a raw leaf value that is ALREADY a well-formed
/// <c>fp:</c>/<c>jkp:tomb:</c> envelope — see <see cref="ValueEnvelopeWriter"/> for the grammar this mirrors —
/// so the replay masking path (the only caller) can pass it through byte-identical instead of re-wrapping an
/// already-masked value in a SECOND envelope, or re-tombstoning it under whatever field name it happens to be
/// echoed back under.
/// </summary>
/// <remarks>
/// <para><b>Why this matters beyond the obvious:</b> <see cref="ValueEnvelopeWriter.WriteTombstone"/> is already a
/// pure function of <c>(jsonType, kind)</c>, so re-tombstoning a value under the SAME field name is trivially
/// idempotent on its own (same inputs, same output) — no special-case needed. The case this class actually fixes
/// is a value echoed back under a DIFFERENT field name than the one that produced it (e.g. a request's
/// <c>authToken</c> tombstone envelope reappearing, verbatim, inside a response field named <c>sessionToken</c>):
/// without this check, the SDK would re-derive <c>kind</c> from the NEW field name and produce a DIFFERENT
/// tombstone string. Checking the raw VALUE's own shape — independent of whatever field it currently sits under —
/// is what makes this idempotent regardless of field-name drift between request and response.</para>
/// <para><b>False-positive bound:</b> both grammars are validated as strictly as <c>ValueEnvelopeWriter</c> itself
/// writes them — exact literal prefix, a jsonType restricted to the four single characters this SDK ever emits
/// (<c>s</c>/<c>n</c>/<c>g</c>/<c>u</c>), a lowercase-ASCII-alnum-only <c>kind</c>/<c>semanticKind</c> token, a
/// non-negative integer <c>keyVersion</c>, and — for <c>fp:</c> — a digest that is EXACTLY 22 base64url characters
/// (the fixed length <see cref="Base64UrlManual.Encode"/> always produces for the 16-byte digest
/// <see cref="FingerprintGenerator.ComputeCorrelationDigest"/> always returns; see that method's remarks). A
/// colon-delimited, fixed-vocabulary token stream this specific is not a shape ordinary business data organically
/// produces; the digest-length constraint alone narrows an accidental collision to effectively zero.</para>
/// </remarks>
internal static class ReplayEnvelopeRecognizer
{
    private const string FingerprintPrefix = "fp:";
    private const string TombstonePrefix = "jkp:tomb:";

    /// <summary>16 bytes base64url-encoded (unpadded) is always exactly 22 characters — see
    /// <see cref="Base64UrlManual.Encode"/>'s remarks.</summary>
    private const int DigestCharLength = 22;

    /// <summary>True when <paramref name="raw"/> is byte-for-byte a well-formed <c>fp:</c> or <c>jkp:tomb:</c>
    /// envelope this SDK could itself have written.</summary>
    public static bool IsAlreadyMaskedEnvelope(string raw)
    {
        if (string.IsNullOrEmpty(raw))
        {
            return false;
        }

        if (raw.StartsWith(TombstonePrefix, StringComparison.Ordinal))
        {
            return IsWellFormedTombstone(raw);
        }

        // Checked after the (longer, more specific) tombstone prefix: "jkp:tomb:..." does not start with "fp:",
        // so order between these two branches does not matter for correctness, only for the trivial optimization
        // of trying the more specific literal first.
        if (raw.StartsWith(FingerprintPrefix, StringComparison.Ordinal))
        {
            return IsWellFormedFingerprint(raw);
        }

        return false;
    }

    /// <summary><c>fp:&lt;jsonType&gt;:&lt;semanticKind&gt;:&lt;keyVersion&gt;:&lt;digest&gt;</c> — 5 colon-separated
    /// tokens (the literal "fp" counts as the first).</summary>
    private static bool IsWellFormedFingerprint(string raw)
    {
        var parts = raw.Split(':');
        if (parts.Length != 5 || parts[0] != "fp")
        {
            return false;
        }

        return IsValidJsonType(parts[1]) &&
               IsLowercaseAsciiAlnumToken(parts[2]) &&
               IsNonNegativeInteger(parts[3]) &&
               IsBase64UrlDigest(parts[4]);
    }

    /// <summary><c>jkp:tomb:&lt;jsonType&gt;:&lt;kind&gt;</c> — 4 colon-separated tokens (the literal "jkp"/"tomb"
    /// count as the first two).</summary>
    private static bool IsWellFormedTombstone(string raw)
    {
        var parts = raw.Split(':');
        if (parts.Length != 4 || parts[0] != "jkp" || parts[1] != "tomb")
        {
            return false;
        }

        return IsValidJsonType(parts[2]) && IsLowercaseAsciiAlnumToken(parts[3]);
    }

    private static bool IsValidJsonType(string token) =>
        token.Length == 1 && token[0] is 's' or 'n' or 'g' or 'u';

    private static bool IsLowercaseAsciiAlnumToken(string token)
    {
        if (token.Length == 0)
        {
            return false;
        }

        foreach (var c in token)
        {
            if (!(char.IsAsciiDigit(c) || (c >= 'a' && c <= 'z')))
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsNonNegativeInteger(string token)
    {
        if (token.Length == 0)
        {
            return false;
        }

        foreach (var c in token)
        {
            if (!char.IsAsciiDigit(c))
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsBase64UrlDigest(string token)
    {
        if (token.Length != DigestCharLength)
        {
            return false;
        }

        foreach (var c in token)
        {
            if (!(char.IsAsciiLetterOrDigit(c) || c is '-' or '_'))
            {
                return false;
            }
        }

        return true;
    }
}
