using Jakapil.Capture.Anonymization;

namespace Jakapil.Capture.Tests.Anonymization;

/// <summary>Verifies ADR-0002 §7's synthetic PII generator: determinism, and that the real email domain is
/// never preserved (the specific security property the ADR calls out by name).</summary>
public sealed class SyntheticPiiGeneratorTests
{
    private static readonly byte[] Key = "test-anon-key"u8.ToArray();
    private static readonly AnonymizationScope Scope = new() { TenantId = "t1", ProjectId = "p1", Environment = "prod" };

    [Fact]
    public void GenerateEmail_NeverPreservesRealDomain()
    {
        var synthetic = SyntheticPiiGenerator.Generate("email", "ali@gercekfirma.com", Key, Scope, "example.com");

        Assert.DoesNotContain("gercekfirma.com", synthetic);
        Assert.EndsWith("@example.com", synthetic);
    }

    [Fact]
    public void GenerateEmail_UsesConfiguredDomain()
    {
        var synthetic = SyntheticPiiGenerator.Generate("email", "someone@real.example", Key, Scope, "customer-staging.test");

        Assert.EndsWith("@customer-staging.test", synthetic);
    }

    [Fact]
    public void Generate_IsDeterministic_SameInputSameOutput()
    {
        var first = SyntheticPiiGenerator.Generate("email", "ali@gercekfirma.com", Key, Scope, "example.com");
        var second = SyntheticPiiGenerator.Generate("email", "ali@gercekfirma.com", Key, Scope, "example.com");

        Assert.Equal(first, second);
    }

    [Fact]
    public void Generate_DifferentRawValues_DifferentOutputs()
    {
        var first = SyntheticPiiGenerator.Generate("email", "alice@example.org", Key, Scope, "example.com");
        var second = SyntheticPiiGenerator.Generate("email", "bob@example.org", Key, Scope, "example.com");

        Assert.NotEqual(first, second);
    }

    [Fact]
    public void GenerateName_NeverContainsOriginalName()
    {
        var synthetic = SyntheticPiiGenerator.Generate("fullName", "Ayşe Yılmaz", Key, Scope, "example.com");

        Assert.DoesNotContain("Ayşe", synthetic);
        Assert.DoesNotContain("Yılmaz", synthetic);
    }

    [Fact]
    public void GenerateFreeText_NeverContainsOriginalText()
    {
        var synthetic = SyntheticPiiGenerator.Generate("description", "met with the customer at their office", Key, Scope, "example.com");

        Assert.DoesNotContain("customer", synthetic);
        Assert.DoesNotContain("office", synthetic);
    }

    [Fact]
    public void GeneratePhone_UsesReservedFictionalRange()
    {
        var synthetic = SyntheticPiiGenerator.Generate("phone", "+905551234567", Key, Scope, "example.com");

        Assert.StartsWith("+1-555-01", synthetic);
    }

    // ---- v1.2.0 type-preserving anonymization (Defect 1 fix) ----------------------------------------------

    [Fact]
    public void Generate_IntegerShape_ProducesPlainIntegerText()
    {
        var synthetic = SyntheticPiiGenerator.Generate(
            "pageSize", "10", Key, Scope, "example.com", SyntheticValueShape.Integer);

        Assert.True(long.TryParse(synthetic, out _), $"'{synthetic}' does not parse as an integer.");
        Assert.DoesNotContain('.', synthetic);
    }

    [Fact]
    public void Generate_IntegerShape_NeverOverflowsInt32()
    {
        // A field policy could route an arbitrarily large number through here — the synthetic replacement
        // must still fit comfortably inside a typical 32-bit consumer's int, regardless of the original's size.
        var synthetic = SyntheticPiiGenerator.Generate(
            "count", "99999999999999999999", Key, Scope, "example.com", SyntheticValueShape.Integer);

        Assert.True(int.TryParse(synthetic, out _), $"'{synthetic}' overflows int32.");
    }

    [Fact]
    public void Generate_DecimalShape_ProducesDecimalText_NeverAWholeNumber()
    {
        var synthetic = SyntheticPiiGenerator.Generate(
            "price", "19.99", Key, Scope, "example.com", SyntheticValueShape.Decimal);

        Assert.Contains('.', synthetic);
        Assert.True(decimal.TryParse(synthetic, System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out _),
            $"'{synthetic}' does not parse as a decimal.");
    }

    [Fact]
    public void Generate_BooleanShape_ProducesTrueOrFalseText()
    {
        var synthetic = SyntheticPiiGenerator.Generate(
            "active", "true", Key, Scope, "example.com", SyntheticValueShape.Boolean);

        Assert.True(synthetic is "true" or "false", $"'{synthetic}' is not a boolean literal.");
    }

    [Fact]
    public void Generate_IntegerShape_IsDeterministic_SameInputSameOutput()
    {
        var first = SyntheticPiiGenerator.Generate("pageSize", "10", Key, Scope, "example.com", SyntheticValueShape.Integer);
        var second = SyntheticPiiGenerator.Generate("pageSize", "10", Key, Scope, "example.com", SyntheticValueShape.Integer);

        Assert.Equal(first, second);
    }

    [Fact]
    public void Generate_IntegerShape_NegativeInput_PreservesSign()
    {
        var synthetic = SyntheticPiiGenerator.Generate("delta", "-42", Key, Scope, "example.com", SyntheticValueShape.Integer);

        Assert.StartsWith("-", synthetic);
        Assert.True(long.TryParse(synthetic, out _), $"'{synthetic}' does not parse as an integer.");
    }

    // InlineData cannot carry an `internal` enum on a `public` xUnit test method (CS0051), so the expected
    // shape travels as its underlying int and is cast back before asserting.
    [Theory]
    [InlineData("10", (int)SyntheticValueShape.Integer)]
    [InlineData("0", (int)SyntheticValueShape.Integer)]
    [InlineData("-3", (int)SyntheticValueShape.Integer)]
    [InlineData("19.99", (int)SyntheticValueShape.Decimal)]
    [InlineData("true", (int)SyntheticValueShape.Boolean)]
    [InlineData("False", (int)SyntheticValueShape.Boolean)]
    [InlineData("abc123", (int)SyntheticValueShape.Text)]
    [InlineData("c9f14b2e-8a31-4f6d-9e02-77aa41b0c5d3", (int)SyntheticValueShape.Text)]
    [InlineData("007", (int)SyntheticValueShape.Integer)]
    public void DetectTransportShape_ClassifiesRawTransportText(string rawValue, int expectedShape)
    {
        Assert.Equal((SyntheticValueShape)expectedShape, SyntheticPiiGenerator.DetectTransportShape(rawValue));
    }
}
