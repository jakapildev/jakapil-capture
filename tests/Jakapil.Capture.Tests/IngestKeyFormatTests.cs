using Jakapil.Capture;

namespace Jakapil.Capture.Tests;

/// <summary>
/// Covers <see cref="IngestKeyFormat"/>, the strict parser for <c>jk_&lt;scopeRef&gt;_&lt;secret&gt;</c> ingest
/// keys. It must accept exactly what the collector accepts and nothing else: the scope reference it yields
/// becomes the anonymization domain, so a lenient parser would silently place a deployment in the wrong digest
/// space instead of failing at startup.
/// </summary>
public sealed class IngestKeyFormatTests
{
    private const string ScopeRef = "0123456789ABCDEF";

    private const string Secret = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";

    private const string WellFormedKey = "jk_" + ScopeRef + "_" + Secret;

    [Fact]
    public void Constants_DescribeTheCollectorsFormat()
    {
        Assert.Equal("jk_", IngestKeyFormat.Prefix);
        Assert.Equal(16, IngestKeyFormat.ScopeRefLength);
        Assert.Equal(64, IngestKeyFormat.SecretLength);
        Assert.Equal(84, IngestKeyFormat.TotalLength);
        Assert.Equal(IngestKeyFormat.TotalLength, WellFormedKey.Length);
    }

    [Fact]
    public void TryParse_WellFormedKey_ReturnsTrue_AndYieldsScopeRef()
    {
        var parsed = IngestKeyFormat.TryParse(WellFormedKey, out var scopeRef);

        Assert.True(parsed);
        Assert.Equal(ScopeRef, scopeRef);
    }

    /// <summary>The scope reference must come from the key's own prefix, not from any fixed position of a
    /// differently shaped input.</summary>
    [Fact]
    public void TryParse_DifferentScopeRef_YieldsThatScopeRef()
    {
        var parsed = IngestKeyFormat.TryParse("jk_FEDCBA9876543210_" + Secret, out var scopeRef);

        Assert.True(parsed);
        Assert.Equal("FEDCBA9876543210", scopeRef);
    }

    [Fact]
    public void TryParse_Null_ReturnsFalse_AndEmptyScopeRef()
    {
        var parsed = IngestKeyFormat.TryParse(null, out var scopeRef);

        Assert.False(parsed);
        Assert.Equal(string.Empty, scopeRef);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("jk_")]
    [InlineData("ik_test")]
    // Legacy-looking key of the right total length but the wrong prefix.
    [InlineData("ik_0123456789ABCDEF_0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")]
    // The prefix is matched ordinally, so case matters.
    [InlineData("JK_0123456789ABCDEF_0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")]
    [InlineData("Jk_0123456789ABCDEF_0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")]
    // Scope ref one character short / one character long.
    [InlineData("jk_0123456789ABCDE_0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")]
    [InlineData("jk_0123456789ABCDEF0_0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")]
    // Lowercase hex is rejected on both halves — the collector issues uppercase only.
    [InlineData("jk_0123456789abcdef_0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")]
    [InlineData("jk_0123456789ABCDEF_0123456789abcdef0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")]
    // 'G' is not a hex digit.
    [InlineData("jk_0123456789ABCDEG_0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")]
    [InlineData("jk_0123456789ABCDEF_G123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDE")]
    // A second separator hidden inside the secret, total length still correct.
    [InlineData("jk_0123456789ABCDEF_0123456789ABCDE_0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")]
    // The separator itself replaced by another character.
    [InlineData("jk_0123456789ABCDEF-0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")]
    // Secret one character short / one character long.
    [InlineData("jk_0123456789ABCDEF_0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDE")]
    [InlineData("jk_0123456789ABCDEF_0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEFA")]
    // Leading/trailing whitespace is not trimmed — configuration errors must surface, not be repaired.
    [InlineData(" jk_0123456789ABCDEF_0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")]
    [InlineData("jk_0123456789ABCDEF_0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF ")]
    public void TryParse_MalformedKey_ReturnsFalse_AndEmptyScopeRef(string ingestKey)
    {
        var parsed = IngestKeyFormat.TryParse(ingestKey, out var scopeRef);

        Assert.False(parsed);
        Assert.Equal(string.Empty, scopeRef);
    }

    /// <summary>Every uppercase-hex character must be accepted in both halves — a rejection here would make
    /// perfectly valid, server-issued keys unusable.</summary>
    [Fact]
    public void TryParse_AllHexDigitsAccepted()
    {
        const string hexScopeRef = "0123456789ABCDEF";
        const string hexSecret = "FEDCBA9876543210" + "0123456789ABCDEF" + "AAAAAAAAAAAAAAAA" + "FFFFFFFFFFFFFFFF";

        var parsed = IngestKeyFormat.TryParse("jk_" + hexScopeRef + "_" + hexSecret, out var scopeRef);

        Assert.True(parsed);
        Assert.Equal(hexScopeRef, scopeRef);
    }

    /// <summary>The parser never throws, whatever it is handed.</summary>
    [Theory]
    [InlineData("jk")]
    [InlineData("j")]
    [InlineData("_")]
    [InlineData("jk_________________________________________________________________________________")]
    public void TryParse_ShortOrDegenerateInput_DoesNotThrow(string ingestKey)
    {
        Assert.False(IngestKeyFormat.TryParse(ingestKey, out _));
    }
}
