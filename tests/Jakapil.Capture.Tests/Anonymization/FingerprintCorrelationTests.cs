using Jakapil.Capture.Anonymization;

namespace Jakapil.Capture.Tests.Anonymization;

/// <summary>
/// Verifies the digest formula's correlation invariants directly (ADR-0002 §6.2/§14), independent of the
/// full <see cref="Anonymizer"/> pipeline.
/// </summary>
/// <remarks>
/// Domain separation is now carried by a single <c>scopeRef</c> — the scope-reference half of the ingest key —
/// instead of three separately configured tenant/project/environment strings. One server-issued value that
/// already identifies exactly one environment of one project of one tenant replaces three strings that nothing
/// validated and that were routinely left empty, so these tests assert the property that actually matters:
/// different scope references never share a digest space, and one scope reference is stable.
/// </remarks>
public sealed class FingerprintCorrelationTests
{
    private static readonly byte[] Key = "customer-secret-key"u8.ToArray();

    private const string ScopeRef = "0123456789ABCDEF";

    /// <summary>INV-A1: jsonType must NOT be part of the digest input — the whole point of the two-axis
    /// design (ADR §6.1) is that a quoted JSON string, a bare JSON number, and a route/query token all produce
    /// the SAME digest for the same semantic role + raw value, so a cross-position correlation edge exists.
    /// This test calls <see cref="FingerprintGenerator.ComputeCorrelationDigest"/> directly (which never takes
    /// jsonType as a parameter at all) to prove the invariant structurally, not just by coincidence.</summary>
    [Fact]
    public void ComputeCorrelationDigest_SameRoleAndValue_SameDigest_RegardlessOfSourcePosition()
    {
        var digestFromQuotedBodyString = FingerprintGenerator.ComputeCorrelationDigest(Key, ScopeRef, "id", "7733");
        var digestFromBareBodyNumber = FingerprintGenerator.ComputeCorrelationDigest(Key, ScopeRef, "id", "7733");
        var digestFromRouteToken = FingerprintGenerator.ComputeCorrelationDigest(Key, ScopeRef, "id", "7733");

        Assert.Equal(digestFromQuotedBodyString, digestFromBareBodyNumber);
        Assert.Equal(digestFromQuotedBodyString, digestFromRouteToken);
    }

    /// <summary>ADR §6.2: two environments must never collide even when they capture the identical raw
    /// production value. Their ingest keys carry different scope references, and that alone is what keeps the
    /// digest spaces apart.</summary>
    [Theory]
    [InlineData("0123456789ABCDEF", "FEDCBA9876543210")]
    [InlineData("AAAAAAAAAAAAAAAA", "AAAAAAAAAAAAAAAB")]
    public void ComputeCorrelationDigest_DifferentScopeRef_DifferentDigest(string scopeRefA, string scopeRefB)
    {
        var digestA = FingerprintGenerator.ComputeCorrelationDigest(Key, scopeRefA, "id", "7733");
        var digestB = FingerprintGenerator.ComputeCorrelationDigest(Key, scopeRefB, "id", "7733");

        Assert.NotEqual(digestA, digestB);
    }

    /// <summary>The scope reference is permanently stable for an environment, so the digest for a given value
    /// must stay identical across processes, restarts, and SDK instances — that stability is what makes
    /// cross-interaction correlation work at all.</summary>
    [Fact]
    public void ComputeCorrelationDigest_SameScopeRef_IsStable()
    {
        var first = FingerprintGenerator.ComputeCorrelationDigest(Key, ScopeRef, "id", "7733");
        var second = FingerprintGenerator.ComputeCorrelationDigest(Key, ScopeRef, "id", "7733");

        Assert.Equal(first, second);
    }

    /// <summary>The scope reference and the semantic kind occupy separate, NUL-delimited positions in the
    /// digest input, so shifting a character from one into the other cannot produce the same digest.</summary>
    [Fact]
    public void ComputeCorrelationDigest_ScopeRefAndSemanticKind_AreSeparateInputPositions()
    {
        var digest = FingerprintGenerator.ComputeCorrelationDigest(Key, "0123456789ABCDE", "Fid", "7733");
        var shifted = FingerprintGenerator.ComputeCorrelationDigest(Key, "0123456789ABCDEF", "id", "7733");

        Assert.NotEqual(digest, shifted);
    }

    [Fact]
    public void ComputeCorrelationDigest_DifferentSemanticKind_DifferentDigest()
    {
        var digestForId = FingerprintGenerator.ComputeCorrelationDigest(Key, ScopeRef, "id", "7733");
        var digestForRef = FingerprintGenerator.ComputeCorrelationDigest(Key, ScopeRef, "ref", "7733");

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

        var digestV1 = FingerprintGenerator.ComputeCorrelationDigest(keyV1, ScopeRef, "id", "7733");
        var digestV2 = FingerprintGenerator.ComputeCorrelationDigest(keyV2, ScopeRef, "id", "7733");

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
        var digestWithLeadingZero = FingerprintGenerator.ComputeCorrelationDigest(Key, ScopeRef, "id", "00123");
        var digestWithoutLeadingZero = FingerprintGenerator.ComputeCorrelationDigest(Key, ScopeRef, "id", "123");

        Assert.NotEqual(digestWithLeadingZero, digestWithoutLeadingZero);
    }

    [Fact]
    public void ComputeCorrelationDigest_IsDeterministic_SameInputsSameOutput()
    {
        var first = FingerprintGenerator.ComputeCorrelationDigest(Key, ScopeRef, "id", "7733");
        var second = FingerprintGenerator.ComputeCorrelationDigest(Key, ScopeRef, "id", "7733");

        Assert.Equal(first, second);
    }

    /// <summary>The synthetic-PII seed shares the same digest input, so it must be separated by scope
    /// reference too — otherwise two environments would synthesize identical fake values for identical real
    /// ones and a cross-environment join would become possible.</summary>
    [Fact]
    public void ComputeSyntheticSeed_DifferentScopeRef_DifferentSeed()
    {
        var seedA = FingerprintGenerator.ComputeSyntheticSeed(Key, "0123456789ABCDEF", "email", "real@customer.com");
        var seedB = FingerprintGenerator.ComputeSyntheticSeed(Key, "FEDCBA9876543210", "email", "real@customer.com");

        Assert.NotEqual(seedA, seedB);
    }
}
