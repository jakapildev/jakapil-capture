namespace Jakapil.Capture.Anonymization;

/// <summary>
/// Manual base64url encoding, shared by both target frameworks (net8.0/net10.0) so a fingerprint digest is
/// byte-for-byte identical regardless of which one the host application runs on.
/// </summary>
/// <remarks>
/// <see cref="System.Buffers.Text.Base64Url"/> only exists from .NET 9 onward; this package also targets
/// net8.0, where that type does not exist. Rather than branching on <c>#if NET9_0_OR_GREATER</c> (which risks
/// the two targets silently drifting to different encodings over time), the encoding is always done by hand
/// here, on both targets, via <see cref="Convert.ToBase64String(byte[])"/> + the standard base64url character
/// substitution (RFC 4648 §5) with padding stripped. This is verified against the server-side
/// <c>Base64Url.IsValid</c> gate in <c>EnvelopeGrammarTests</c>.
/// </remarks>
internal static class Base64UrlManual
{
    /// <summary>Encodes the given bytes as unpadded base64url: standard base64, then <c>+</c>→<c>-</c>,
    /// <c>/</c>→<c>_</c>, trailing <c>=</c> padding stripped. 16 bytes (128 bit, the ADR-0002 §6.2 digest
    /// length) always produce exactly 22 characters and never contain <c>:</c> — the envelope's token
    /// separator — so encoding never breaks the <c>fp:</c>/<c>jkp:tomb:</c> grammar.</summary>
    public static string Encode(ReadOnlySpan<byte> bytes)
    {
        var base64 = Convert.ToBase64String(bytes);
        return base64.Replace('+', '-').Replace('/', '_').TrimEnd('=');
    }

    /// <summary>Decodes an unpadded base64url string (RFC 4648 §5) back to bytes: <c>-</c>→<c>+</c>,
    /// <c>_</c>→<c>/</c>, padding restored from the string length, then standard base64 decode. Used by
    /// ADR-0003's replay-signature verification (<c>sig</c>, <c>n</c> header fields) — added alongside
    /// <see cref="Encode"/> for the same "one hand-written implementation on every target framework" reason.</summary>
    /// <exception cref="FormatException">The input is not valid base64url (wrong length/alphabet).</exception>
    public static byte[] Decode(string base64Url)
    {
        var base64 = base64Url.Replace('-', '+').Replace('_', '/');
        base64 += (base64.Length % 4) switch
        {
            0 => string.Empty,
            2 => "==",
            3 => "=",
            _ => throw new FormatException("Invalid base64url string length."),
        };

        return Convert.FromBase64String(base64);
    }
}
