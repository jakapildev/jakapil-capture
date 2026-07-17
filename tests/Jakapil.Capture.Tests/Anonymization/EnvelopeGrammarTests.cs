using Jakapil.Capture.Anonymization;

namespace Jakapil.Capture.Tests.Anonymization;

/// <summary>
/// Verifies every envelope this SDK produces parses under the exact grammar the server-side
/// <c>Jakapil.Core.DataFlow.ValueEnvelope.TryParse</c> enforces (ADR-0002 §6.3/§8). Since the server-side Core
/// assembly cannot be referenced from this repo (Contracts/Capture must stay Core-free — ARCH invariant), the
/// grammar is re-implemented here, by hand, token-for-token from the ADR text, and used purely as an
/// independent verifier of what <see cref="ValueEnvelopeWriter"/> produces.
/// </summary>
public sealed class EnvelopeGrammarTests
{
    private static readonly HashSet<string> ValidJsonTypes = ["s", "n", "g", "u"];

    /// <summary>Mirrors <c>ValueEnvelope.TryParse</c>'s fingerprint grammar check.</summary>
    private static bool IsValidFingerprintEnvelope(string envelope)
    {
        var tokens = envelope.Split(':');
        if (tokens.Length != 5 || tokens[0] != "fp")
        {
            return false;
        }

        var jsonType = tokens[1];
        var semanticKind = tokens[2];
        var keyVersionRaw = tokens[3];
        var digest = tokens[4];

        if (!ValidJsonTypes.Contains(jsonType) || !IsValidNameToken(semanticKind))
        {
            return false;
        }

        if (!int.TryParse(keyVersionRaw, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out _))
        {
            return false;
        }

        return IsValidBase64UrlDigest(digest);
    }

    /// <summary>Mirrors <c>ValueEnvelope.TryParse</c>'s tombstone grammar check.</summary>
    private static bool IsValidTombstoneEnvelope(string envelope)
    {
        var tokens = envelope.Split(':');
        if (tokens.Length != 4 || tokens[0] != "jkp" || tokens[1] != "tomb")
        {
            return false;
        }

        return ValidJsonTypes.Contains(tokens[2]) && IsValidNameToken(tokens[3]);
    }

    private static bool IsValidNameToken(string token)
    {
        if (token.Length == 0)
        {
            return false;
        }

        foreach (var c in token)
        {
            if (!char.IsAsciiLetterOrDigit(c))
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsValidBase64UrlDigest(string digest)
    {
        if (digest.Length == 0)
        {
            return false;
        }

        foreach (var c in digest)
        {
            var isBase64UrlChar = char.IsAsciiLetterOrDigit(c) || c is '-' or '_';
            if (!isBase64UrlChar)
            {
                return false;
            }
        }

        // Re-pad and decode standard base64 to check the byte length (>= 16 bytes / 128 bit required).
        var standard = digest.Replace('-', '+').Replace('_', '/');
        var padded = standard.PadRight(standard.Length + ((4 - (standard.Length % 4)) % 4), '=');
        var decoded = Convert.FromBase64String(padded);
        return decoded.Length >= 16;
    }

    [Theory]
    [InlineData("s", "id", 1)]
    [InlineData("n", "id", 1)]
    [InlineData("g", "ref", 2)]
    [InlineData("u", "key", 0)]
    public void WriteFingerprint_ProducesGrammarValidEnvelope(string jsonType, string semanticKind, int keyVersion)
    {
        var digest = FingerprintGenerator.ComputeCorrelationDigest(
            "test-key"u8, "tenant", "project", "env", semanticKind, "some-value");
        var envelope = ValueEnvelopeWriter.WriteFingerprint(jsonType, semanticKind, keyVersion, digest);

        Assert.True(IsValidFingerprintEnvelope(envelope), $"Envelope '{envelope}' failed grammar validation.");
    }

    [Theory]
    [InlineData("s", "password")]
    [InlineData("u", "token")]
    public void WriteTombstone_ProducesGrammarValidEnvelope(string jsonType, string kind)
    {
        var envelope = ValueEnvelopeWriter.WriteTombstone(jsonType, kind);

        Assert.True(IsValidTombstoneEnvelope(envelope), $"Envelope '{envelope}' failed grammar validation.");
    }

    [Fact]
    public void WriteFingerprint_NeverContainsExtraColon_InDigest()
    {
        var digest = FingerprintGenerator.ComputeCorrelationDigest("k"u8, "t", "p", "e", "id", "value-with-!@#-chars");

        Assert.DoesNotContain(':', digest);
    }

    [Fact]
    public void Base64UrlManual_EncodesSixteenBytes_AsTwentyTwoUnpaddedChars()
    {
        var bytes = new byte[16];
        Random.Shared.NextBytes(bytes);

        var encoded = Base64UrlManual.Encode(bytes);

        Assert.Equal(22, encoded.Length);
        Assert.DoesNotContain('+', encoded);
        Assert.DoesNotContain('/', encoded);
        Assert.DoesNotContain('=', encoded);
        Assert.DoesNotContain(':', encoded);
    }

    [Fact]
    public void Base64UrlManual_EncodedOutput_DecodesBackToOriginalBytes()
    {
        var bytes = new byte[16];
        for (var i = 0; i < bytes.Length; i++)
        {
            bytes[i] = (byte)(i * 17 + 3);
        }

        var encoded = Base64UrlManual.Encode(bytes);
        var standard = encoded.Replace('-', '+').Replace('_', '/');
        var padded = standard.PadRight(standard.Length + ((4 - (standard.Length % 4)) % 4), '=');
        var decoded = Convert.FromBase64String(padded);

        Assert.Equal(bytes, decoded);
    }
}
