using Jakapil.Capture.Anonymization;

namespace Jakapil.Capture.Tests.Anonymization;

/// <summary>
/// Verifies the digest formula's correlation invariants directly (ADR-0002 §6.2/§14), independent of the
/// full <see cref="Anonymizer"/> pipeline.
/// </summary>
public sealed class FingerprintCorrelationTests
{
    private static readonly byte[] Key = "customer-secret-key"u8.ToArray();

    /// <summary>INV-A1: jsonType must NOT be part of the digest input — the whole point of the two-axis
    /// design (ADR §6.1) is that a quoted JSON string, a bare JSON number, and a route/query token all produce
    /// the SAME digest for the same semantic role + raw value, so a cross-position correlation edge exists.
    /// This test calls <see cref="FingerprintGenerator.ComputeCorrelationDigest"/> directly (which never takes
    /// jsonType as a parameter at all) to prove the invariant structurally, not just by coincidence.</summary>
    [Fact]
    public void ComputeCorrelationDigest_SameRoleAndValue_SameDigest_RegardlessOfSourcePosition()
    {
        var digestFromQuotedBodyString = FingerprintGenerator.ComputeCorrelationDigest(
            Key, "tenant-1", "project-1", "prod", "id", "7733");
        var digestFromBareBodyNumber = FingerprintGenerator.ComputeCorrelationDigest(
            Key, "tenant-1", "project-1", "prod", "id", "7733");
        var digestFromRouteToken = FingerprintGenerator.ComputeCorrelationDigest(
            Key, "tenant-1", "project-1", "prod", "id", "7733");

        Assert.Equal(digestFromQuotedBodyString, digestFromBareBodyNumber);
        Assert.Equal(digestFromQuotedBodyString, digestFromRouteToken);
    }

    [Theory]
    [InlineData("tenant-a", "tenant-b")]
    public void ComputeCorrelationDigest_DifferentTenant_DifferentDigest(string tenantA, string tenantB)
    {
        var digestA = FingerprintGenerator.ComputeCorrelationDigest(Key, tenantA, "project", "prod", "id", "7733");
        var digestB = FingerprintGenerator.ComputeCorrelationDigest(Key, tenantB, "project", "prod", "id", "7733");

        Assert.NotEqual(digestA, digestB);
    }

    [Fact]
    public void ComputeCorrelationDigest_DifferentProject_DifferentDigest()
    {
        var digestA = FingerprintGenerator.ComputeCorrelationDigest(Key, "tenant", "project-a", "prod", "id", "7733");
        var digestB = FingerprintGenerator.ComputeCorrelationDigest(Key, "tenant", "project-b", "prod", "id", "7733");

        Assert.NotEqual(digestA, digestB);
    }

    [Fact]
    public void ComputeCorrelationDigest_DifferentEnvironment_DifferentDigest()
    {
        var digestA = FingerprintGenerator.ComputeCorrelationDigest(Key, "tenant", "project", "staging", "id", "7733");
        var digestB = FingerprintGenerator.ComputeCorrelationDigest(Key, "tenant", "project", "production", "id", "7733");

        Assert.NotEqual(digestA, digestB);
    }

    [Fact]
    public void ComputeCorrelationDigest_DifferentSemanticKind_DifferentDigest()
    {
        var digestForId = FingerprintGenerator.ComputeCorrelationDigest(Key, "t", "p", "e", "id", "7733");
        var digestForRef = FingerprintGenerator.ComputeCorrelationDigest(Key, "t", "p", "e", "ref", "7733");

        Assert.NotEqual(digestForId, digestForRef);
    }

    /// <summary>ADR §14: different key versions are separate, non-correlating key spaces. The digest itself
    /// does not take keyVersion as an input (only the ENVELOPE carries the version tag), so this test proves
    /// domain separation via different key BYTES (what a rotation actually changes), and confirms the envelope
    /// text still differs since the version tag differs even when (hypothetically) the digest collided.</summary>
    [Fact]
    public void KeyRotation_DifferentKeyBytes_DifferentDigest_AndEnvelopeCarriesVersion()
    {
        var keyV1 = "key-version-1"u8.ToArray();
        var keyV2 = "key-version-2"u8.ToArray();

        var digestV1 = FingerprintGenerator.ComputeCorrelationDigest(keyV1, "t", "p", "e", "id", "7733");
        var digestV2 = FingerprintGenerator.ComputeCorrelationDigest(keyV2, "t", "p", "e", "id", "7733");

        Assert.NotEqual(digestV1, digestV2);

        var envelopeV1 = ValueEnvelopeWriter.WriteFingerprint("u", "id", keyVersion: 1, digestV1);
        var envelopeV2 = ValueEnvelopeWriter.WriteFingerprint("u", "id", keyVersion: 2, digestV2);

        Assert.Contains(":1:", envelopeV1);
        Assert.Contains(":2:", envelopeV2);
        Assert.NotEqual(envelopeV1, envelopeV2);
    }

    /// <summary>ADR §6.2: canonicalValue is raw text, no numeric normalization — a leading-zero string like
    /// "00123" must NOT collide with "123", because leading zeros can be semantically meaningful for some
    /// systems and it is not safe to assume otherwise for an unknown field.</summary>
    [Fact]
    public void ComputeCorrelationDigest_LeadingZeroValue_DoesNotCollideWithNormalizedValue()
    {
        var digestWithLeadingZero = FingerprintGenerator.ComputeCorrelationDigest(Key, "t", "p", "e", "id", "00123");
        var digestWithoutLeadingZero = FingerprintGenerator.ComputeCorrelationDigest(Key, "t", "p", "e", "id", "123");

        Assert.NotEqual(digestWithLeadingZero, digestWithoutLeadingZero);
    }

    [Fact]
    public void ComputeCorrelationDigest_IsDeterministic_SameInputsSameOutput()
    {
        var first = FingerprintGenerator.ComputeCorrelationDigest(Key, "t", "p", "e", "id", "7733");
        var second = FingerprintGenerator.ComputeCorrelationDigest(Key, "t", "p", "e", "id", "7733");

        Assert.Equal(first, second);
    }
}
