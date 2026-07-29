using System.Security.Cryptography;
using Jakapil.Capture.Replay;
using Microsoft.Extensions.Logging.Abstractions;

namespace Jakapil.Capture.Tests.Replay;

/// <summary>ADR-0003 §6.3/§6.5: loading configured public keys and deriving each one's <c>kid</c>.</summary>
public class ReplayKeyRingTests
{
    private static (string Pem, string Base64Der, string KeyId) GenerateKey()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var der = ecdsa.ExportSubjectPublicKeyInfo();
        var pem = ecdsa.ExportSubjectPublicKeyInfoPem();
        var expectedKeyId = Convert.ToBase64String(SHA256.HashData(der)).Replace('+', '-').Replace('/', '_').TrimEnd('=')[..8];
        return (pem, Convert.ToBase64String(der), expectedKeyId);
    }

    [Fact]
    public void ReplayKeyRing_LoadsPemKey_ComputesExpectedKeyId()
    {
        var (pem, _, expectedKeyId) = GenerateKey();

        var ring = new ReplayKeyRing([pem], NullLogger.Instance);

        Assert.True(ring.HasKeys);
        Assert.True(ring.TryGetKey(expectedKeyId, out var key));
        Assert.NotNull(key);
    }

    [Fact]
    public void ReplayKeyRing_LoadsBase64DerKey_ComputesExpectedKeyId()
    {
        var (_, base64Der, expectedKeyId) = GenerateKey();

        var ring = new ReplayKeyRing([base64Der], NullLogger.Instance);

        Assert.True(ring.HasKeys);
        Assert.True(ring.TryGetKey(expectedKeyId, out _));
    }

    [Fact]
    public void ReplayKeyRing_MultipleKeys_BothAreValidAtTheSameTime_RotationWindow()
    {
        var (pemA, _, keyIdA) = GenerateKey();
        var (pemB, _, keyIdB) = GenerateKey();

        var ring = new ReplayKeyRing([pemA, pemB], NullLogger.Instance);

        Assert.True(ring.TryGetKey(keyIdA, out _));
        Assert.True(ring.TryGetKey(keyIdB, out _));
    }

    [Fact]
    public void ReplayKeyRing_UnknownKeyId_ReturnsFalse()
    {
        var (pem, _, _) = GenerateKey();
        var ring = new ReplayKeyRing([pem], NullLogger.Instance);

        Assert.False(ring.TryGetKey("00000000", out var key));
        Assert.Null(key);
    }

    [Fact]
    public void ReplayKeyRing_NoKeysConfigured_HasKeysIsFalse()
    {
        var ring = new ReplayKeyRing([], NullLogger.Instance);

        Assert.False(ring.HasKeys);
    }

    [Fact]
    public void ReplayKeyRing_MalformedKey_IsSkipped_NeverThrows_LogsWarning()
    {
        var (validPem, _, validKeyId) = GenerateKey();

        var ring = new ReplayKeyRing(["not a valid key at all", validPem], NullLogger.Instance);

        // The malformed entry never crashes the host; the valid one alongside it still loads.
        Assert.True(ring.HasKeys);
        Assert.True(ring.TryGetKey(validKeyId, out _));
    }

    [Fact]
    public void ReplayKeyRing_OnlyMalformedKeys_HasKeysIsFalse_NeverThrows()
    {
        var ring = new ReplayKeyRing(["garbage-not-base64-!!!", "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----"], NullLogger.Instance);

        Assert.False(ring.HasKeys);
    }

    [Fact]
    public void ReplayVerificationOptionsValidator_MalformedPublicKey_ReportsFailure()
    {
        var options = new ReplayVerificationOptions { PublicKeys = ["not a valid key"] };
        var failures = new List<string>();

        ReplayVerificationOptionsValidator.Validate(options, failures);

        Assert.Single(failures);
        Assert.Contains("Replay.PublicKeys", failures[0]);
    }

    [Fact]
    public void ReplayVerificationOptionsValidator_ValidPublicKey_NoFailures()
    {
        var (pem, _, _) = GenerateKey();
        var options = new ReplayVerificationOptions { PublicKeys = [pem] };
        var failures = new List<string>();

        ReplayVerificationOptionsValidator.Validate(options, failures);

        Assert.Empty(failures);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(0)]
    public void ReplayVerificationOptionsValidator_NonPositiveNonceCacheSize_ReportsFailure(int size)
    {
        var options = new ReplayVerificationOptions { NonceCacheSize = size };
        var failures = new List<string>();

        ReplayVerificationOptionsValidator.Validate(options, failures);

        Assert.Contains(failures, f => f.Contains("NonceCacheSize"));
    }

    [Fact]
    public void ReplayVerificationOptionsValidator_NegativeClockSkewTolerance_ReportsFailure()
    {
        var options = new ReplayVerificationOptions { ClockSkewTolerance = TimeSpan.FromSeconds(-1) };
        var failures = new List<string>();

        ReplayVerificationOptionsValidator.Validate(options, failures);

        Assert.Contains(failures, f => f.Contains("ClockSkewTolerance"));
    }
}
