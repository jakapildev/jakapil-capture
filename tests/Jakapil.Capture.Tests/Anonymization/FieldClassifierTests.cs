using Jakapil.Capture.Anonymization;

namespace Jakapil.Capture.Tests.Anonymization;

/// <summary>Verifies the ADR-0002 §5 classification priority order and the fail-safe (INV-A3) defaults.</summary>
public sealed class FieldClassifierTests
{
    [Theory]
    [InlineData("password")]
    [InlineData("Token")]
    [InlineData("apiKey")]
    [InlineData("Authorization")]
    [InlineData("cookie")]
    public void KnownSecretFieldNames_ClassifyAsSecretTombstone(string fieldName)
    {
        var result = FieldClassifier.Classify(fieldName, LeafValueKind.String, "some-secret-value", null);

        Assert.Equal(FieldClass.SecretTombstone, result);
    }

    [Theory]
    [InlineData("email")]
    [InlineData("phone")]
    [InlineData("fullName")]
    [InlineData("address")]
    public void KnownPiiFieldNames_ClassifyAsSyntheticPii(string fieldName)
    {
        var result = FieldClassifier.Classify(fieldName, LeafValueKind.String, "some-value", null);

        Assert.Equal(FieldClass.SyntheticPii, result);
    }

    [Theory]
    [InlineData("description")]
    [InlineData("note")]
    [InlineData("message")]
    [InlineData("comment")]
    public void FreeTextFieldNames_ClassifyAsSyntheticPii_NotSafeLiteral(string fieldName)
    {
        var result = FieldClassifier.Classify(fieldName, LeafValueKind.String, "met with the customer yesterday", null);

        Assert.Equal(FieldClass.SyntheticPii, result);
    }

    [Theory]
    [InlineData("currency", "TRY")]
    [InlineData("status", "active")]
    [InlineData("type", "standard")]
    public void SafeLiteralAllowlistNames_ClassifyAsSafeLiteral(string fieldName, string value)
    {
        var result = FieldClassifier.Classify(fieldName, LeafValueKind.String, value, null);

        Assert.Equal(FieldClass.SafeLiteral, result);
    }

    [Theory]
    [InlineData("quantity")]
    [InlineData("page")]
    [InlineData("limit")]
    public void SafeLiteralAllowlistNames_NumericValue_ClassifyAsSafeLiteral(string fieldName)
    {
        var result = FieldClassifier.Classify(fieldName, LeafValueKind.Number, "2", null);

        Assert.Equal(FieldClass.SafeLiteral, result);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void BooleanValue_AlwaysSafeLiteral_RegardlessOfFieldName(bool _)
    {
        // fieldName deliberately looks PII-ish; a boolean value must still win (ADR §2: boolean is explicitly
        // listed among the enum-like SafeLiteral examples, and there is no PII shape for true/false).
        var result = FieldClassifier.Classify("email", LeafValueKind.BoolOrNull, null, null);

        Assert.Equal(FieldClass.SafeLiteral, result);
    }

    [Theory]
    [InlineData("id")]
    [InlineData("customerId")]
    [InlineData("productId")]
    [InlineData("product_id")]
    [InlineData("category-ref")]
    [InlineData("sessionKey")]
    [InlineData("productIds")]
    public void IdRefKeySuffixedNames_ClassifyAsFlowFingerprint(string fieldName)
    {
        var result = FieldClassifier.Classify(fieldName, LeafValueKind.String, "c9f14b2e-8a31-4f6d-9e02-77aa41b0c5d3", null);

        Assert.Equal(FieldClass.FlowFingerprint, result);
    }

    /// <summary>Regression guard for the word-boundary logic in <see cref="FieldNameRules.ExtractIdentifierRole"/>:
    /// "valid" ends in the letters "id" but is a single lowercase word with no camelCase/snake_case boundary,
    /// so it must NOT be mistaken for an "...Id" suffix (which would wrongly fingerprint an ordinary boolean-ish
    /// field). Likewise "grid" must not match.</summary>
    [Theory]
    [InlineData("valid")]
    [InlineData("grid")]
    [InlineData("android")]
    public void NamesEndingInIdLetters_ButNotAsCamelCaseSuffix_DoNotMatchIdentifierRole(string fieldName)
    {
        var role = FieldNameRules.ExtractIdentifierRole(fieldName);

        Assert.Null(role);
    }

    /// <summary>An unnamed/unknown string that looks identifier-shaped (GUID) falls back to FlowFingerprint —
    /// fail-safe (INV-A3): ambiguous is resolved toward correlation-preserving irreversibility, not plaintext.</summary>
    [Fact]
    public void UnknownFieldName_GuidShapedValue_FallsBackToFlowFingerprint()
    {
        var result = FieldClassifier.Classify("somethingUnrecognized", LeafValueKind.String, "c9f14b2e-8a31-4f6d-9e02-77aa41b0c5d3", null);

        Assert.Equal(FieldClass.FlowFingerprint, result);
    }

    /// <summary>An unnamed/unknown ordinary string (no identifier shape, no known name) falls back to
    /// SyntheticPii — INV-A3: "belirsiz kalan alan SafeLiteral olmaz" (an ambiguous field is never SafeLiteral).</summary>
    [Fact]
    public void UnknownFieldName_OrdinaryString_FallsBackToSyntheticPii_NeverSafeLiteral()
    {
        var result = FieldClassifier.Classify("someWeirdUnrecognizedField", LeafValueKind.String, "hello there", null);

        Assert.Equal(FieldClass.SyntheticPii, result);
        Assert.NotEqual(FieldClass.SafeLiteral, result);
    }

    /// <summary>An unnamed, unknown bare JSON number with no id/ref/key-suffixed name is treated as an
    /// ordinary measure by default (a bare number has no PII shape) — this is a deliberate, documented
    /// judgment call; see the phase report's open question about whether this default should be narrower.</summary>
    [Fact]
    public void UnknownFieldName_NumericValue_DefaultsToSafeLiteral()
    {
        var result = FieldClassifier.Classify("someMeasure", LeafValueKind.Number, "42", null);

        Assert.Equal(FieldClass.SafeLiteral, result);
    }

    /// <summary>ADR §5 priority #1: customer FieldPolicy always wins, even over a built-in secret rule.</summary>
    [Fact]
    public void CustomerFieldPolicy_OverridesBuiltInSecretRule()
    {
        var policy = new Dictionary<string, FieldClass>(StringComparer.OrdinalIgnoreCase)
        {
            ["password"] = FieldClass.SafeLiteral,
        };

        var result = FieldClassifier.Classify("password", LeafValueKind.String, "not-actually-secret-here", policy);

        Assert.Equal(FieldClass.SafeLiteral, result);
    }

    [Fact]
    public void CustomerFieldPolicy_OverridesBuiltInSafeLiteralRule_ToDropped()
    {
        var policy = new Dictionary<string, FieldClass>(StringComparer.OrdinalIgnoreCase)
        {
            ["currency"] = FieldClass.Dropped,
        };

        var result = FieldClassifier.Classify("currency", LeafValueKind.String, "TRY", policy);

        Assert.Equal(FieldClass.Dropped, result);
    }
}
