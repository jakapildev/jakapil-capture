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

    /// <summary>
    /// Regression test for the field bug report (v1.2.0): a bare, generic <c>name</c> field must be classified
    /// using its ENCLOSING object's field name, not on its own name alone. <c>$.customer.name</c> — a person
    /// context — resolves to SyntheticPii; see <see cref="GenericName_NonPersonOrMissingContext_ClassifiesAsSafeLiteral"/>
    /// for the counter-example (<c>$.catalogTypes[].name</c>) that motivated this fix.
    /// </summary>
    [Theory]
    [InlineData("customer")]
    [InlineData("Customer")]
    [InlineData("user")]
    [InlineData("billingAddress")]
    [InlineData("shippingAddress")]
    public void GenericName_PersonContextParent_ClassifiesAsSyntheticPii(string parentFieldName)
    {
        var result = FieldClassifier.Classify("name", LeafValueKind.String, "Ayşe Yılmaz", null, parentFieldName);

        Assert.Equal(FieldClass.SyntheticPii, result);
    }

    /// <summary>
    /// Lead-review regression: PLURAL REST collection parent names (<c>GET /api/users</c> →
    /// <c>{ "users": [ { "name": "..." } ] }</c>) must ALSO be recognized as person context — this is the most
    /// common shape a person record appears in, and <see cref="FieldNameRules.Normalize"/> does not singularize
    /// on its own, so without <see cref="FieldNameRules.HasPersonContext"/>'s singular-candidate matching this
    /// leaked real PII as plaintext. See <see cref="GenericName_PluralNonPersonContextParent_ClassifiesAsSafeLiteral"/>
    /// for the required counter-example proving this does not degrade into "every plural matches".
    /// </summary>
    [Theory]
    [InlineData("users")]
    [InlineData("customers")]
    [InlineData("employees")]
    [InlineData("members")]
    [InlineData("accounts")]
    [InlineData("addresses")]
    public void GenericName_PluralPersonContextParent_ClassifiesAsSyntheticPii(string parentFieldName)
    {
        var result = FieldClassifier.Classify("name", LeafValueKind.String, "Ahmet Yılmaz", null, parentFieldName);

        Assert.Equal(FieldClass.SyntheticPii, result);
    }

    /// <summary>A plural of a NON-person context word must still resolve to SafeLiteral — proves the
    /// singularization fix (<see cref="FieldNameRules.HasPersonContext"/>) widens matching only for words that
    /// actually singularize into a listed person-context word, not indiscriminately for any plural.</summary>
    [Theory]
    [InlineData("companies")]
    [InlineData("catalogTypes")]
    public void GenericName_PluralNonPersonContextParent_ClassifiesAsSafeLiteral(string parentFieldName)
    {
        var result = FieldClassifier.Classify("name", LeafValueKind.String, "Acme Corp", null, parentFieldName);

        Assert.Equal(FieldClass.SafeLiteral, result);
    }

    /// <summary>
    /// The exact false-positive from the bug report: <c>GET /api/catalog-types</c> returns
    /// <c>{ "catalogTypes": [ { "name": "Mug" }, ... ] }</c> — a product-category label, not a person — and the
    /// old rule (bare <c>name</c> treated like <c>fullName</c>) rewrote it to a synthetic person name on every
    /// capture, producing a 100%-reproducible false regression when the generated scenario replayed against the
    /// live API. A root-level <c>name</c> with no enclosing object (<c>parentFieldName: null</c>) must also stay
    /// SafeLiteral — the same rule, just with no context at all rather than a non-person one.
    /// </summary>
    [Theory]
    [InlineData("catalogTypes")]
    [InlineData("products")]
    [InlineData(null)]
    public void GenericName_NonPersonOrMissingContext_ClassifiesAsSafeLiteral(string? parentFieldName)
    {
        var result = FieldClassifier.Classify("name", LeafValueKind.String, "Mug", null, parentFieldName);

        Assert.Equal(FieldClass.SafeLiteral, result);
    }

    /// <summary>Strong-signal PII names (<c>fullName</c>/<c>firstName</c>/<c>lastName</c>/<c>surname</c>) are
    /// NOT context-sensitive — the v1.2.0 fix touches only the generic <c>name</c>, never these — so they must
    /// classify as SyntheticPii both with and without a (non-person) parent context.</summary>
    [Theory]
    [InlineData("fullName", null)]
    [InlineData("firstName", null)]
    [InlineData("lastName", "catalogTypes")]
    [InlineData("surname", "catalogTypes")]
    public void StrongSignalPiiNames_ClassifyAsSyntheticPii_RegardlessOfContext(string fieldName, string? parentFieldName)
    {
        var result = FieldClassifier.Classify(fieldName, LeafValueKind.String, "Ayşe Yılmaz", null, parentFieldName);

        Assert.Equal(FieldClass.SyntheticPii, result);
    }

    /// <summary>ADR §5 priority #1: customer FieldPolicy always wins, even over the new context-sensitive
    /// default for generic <c>name</c> — a customer whose schema needs bare <c>name</c> treated as PII in a
    /// context this heuristic does not recognize can still force it via <see cref="AnonymizationOptions.FieldPolicy"/>.</summary>
    [Fact]
    public void CustomerFieldPolicy_OverridesContextSensitiveNameDefault_ToSyntheticPii()
    {
        var policy = new Dictionary<string, FieldClass>(StringComparer.OrdinalIgnoreCase)
        {
            ["name"] = FieldClass.SyntheticPii,
        };

        var result = FieldClassifier.Classify("name", LeafValueKind.String, "Mug", policy, "catalogTypes");

        Assert.Equal(FieldClass.SyntheticPii, result);
    }
}
