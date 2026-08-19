namespace Jakapil.Capture;

/// <summary>
/// Parses the Jakapil ingest key, whose shape is <c>jk_&lt;scopeRef&gt;_&lt;secret&gt;</c>.
/// </summary>
/// <remarks>
/// <para>
/// The key is issued by the Jakapil UI and carries two independent parts:
/// </para>
/// <list type="bullet">
/// <item><c>scopeRef</c> — exactly 16 uppercase-hex characters. A permanently stable, non-secret label of the
/// target environment. The collector already knows it (it stores it next to the environment) and verifies that
/// the prefix of a presented key matches; the SDK uses it as the domain-separation scope every anonymization
/// digest is derived under.</item>
/// <item><c>secret</c> — exactly 64 uppercase-hex characters. The only half the collector hashes and compares.
/// This SDK never needs it in isolation, which is why it is deliberately NOT surfaced by
/// <see cref="TryParse"/>: the whole key is sent verbatim in the <c>X-Jakapil-Key</c> header, so splitting the
/// secret into its own string would only duplicate secret material in memory for no purpose.</item>
/// </list>
/// <para>
/// Parsing is <b>strict</b> and mirrors the collector's own parser exactly — same literal prefix, same fixed
/// lengths, same uppercase-hex alphabet. Every comparison is ordinal/culture-invariant, so the result cannot
/// vary with the host's current culture. A key that does not parse is rejected at startup by
/// <c>JakapilCaptureOptionsValidator</c> rather than being silently coerced.
/// </para>
/// </remarks>
internal static class IngestKeyFormat
{
    /// <summary>The literal, case-sensitive key prefix.</summary>
    public const string Prefix = "jk_";

    /// <summary>The exact character count of the scope-reference half.</summary>
    public const int ScopeRefLength = 16;

    /// <summary>The exact character count of the secret half.</summary>
    public const int SecretLength = 64;

    /// <summary>The only valid total length: prefix + scopeRef + the single separator + secret.</summary>
    public const int TotalLength = 3 + ScopeRefLength + 1 + SecretLength;

    /// <summary>The human-readable shape, reused verbatim in validation failure messages.</summary>
    public const string ExpectedShape = "jk_<16 uppercase-hex scope ref>_<64 uppercase-hex secret>";

    /// <summary>
    /// Attempts to read the scope reference out of <paramref name="ingestKey"/>. Returns <c>false</c> — never
    /// throws — for a null, empty, wrong-length, wrong-prefix, wrongly-separated, or non-uppercase-hex key.
    /// </summary>
    /// <param name="ingestKey">The raw ingest key exactly as configured.</param>
    /// <param name="scopeRef">The 16-character scope reference on success; <see cref="string.Empty"/> otherwise.</param>
    public static bool TryParse(string? ingestKey, out string scopeRef)
    {
        scopeRef = string.Empty;

        if (ingestKey is null || ingestKey.Length != TotalLength)
        {
            return false;
        }

        if (!ingestKey.StartsWith(Prefix, StringComparison.Ordinal))
        {
            return false;
        }

        var candidate = ingestKey.AsSpan();
        if (candidate[Prefix.Length + ScopeRefLength] != '_')
        {
            return false;
        }

        var scopeRefSpan = candidate.Slice(Prefix.Length, ScopeRefLength);
        var secretSpan = candidate.Slice(Prefix.Length + ScopeRefLength + 1, SecretLength);

        // The fixed total length plus the uppercase-hex alphabet (which excludes '_') is what guarantees the
        // "exactly one separator after the prefix" rule structurally — no extra underscore can hide anywhere.
        if (!IsUppercaseHex(scopeRefSpan) || !IsUppercaseHex(secretSpan))
        {
            return false;
        }

        scopeRef = scopeRefSpan.ToString();
        return true;
    }

    /// <summary>Ordinal, culture-invariant uppercase-hex test — explicit ranges rather than any
    /// culture-sensitive casing API.</summary>
    private static bool IsUppercaseHex(ReadOnlySpan<char> value)
    {
        foreach (var c in value)
        {
            if (c is not (>= '0' and <= '9') and not (>= 'A' and <= 'F'))
            {
                return false;
            }
        }

        return true;
    }
}
