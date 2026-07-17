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
}
