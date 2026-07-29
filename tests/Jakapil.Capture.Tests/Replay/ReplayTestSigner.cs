using System.Security.Cryptography;
using Jakapil.Capture.Anonymization;
using Jakapil.Capture.Replay;

namespace Jakapil.Capture.Tests.Replay;

/// <summary>
/// Test-only stand-in for the Jakapil Runner's signing side (ADR-0003 §6.2/§6.3, PLAN 15d-16 — NOT this repo's
/// scope, but a test double needs to build byte-identical signed headers to exercise the SDK's verifier).
/// Deliberately reuses the SDK's OWN <see cref="ReplayCanonicalString"/>/<see cref="Base64UrlManual"/> — this is
/// intentional: the whole point of the ADR-0003 §6.2 binding format is that both sides build the identical
/// string independently, so using the SDK's own builder here is exactly what a correct, independent Runner
/// implementation would also produce.
/// </summary>
internal static class ReplayTestSigner
{
    public static (string Pem, ECDsa PrivateKey, string KeyId) GenerateKeyPair()
    {
        var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var pem = ecdsa.ExportSubjectPublicKeyInfoPem();
        var der = ecdsa.ExportSubjectPublicKeyInfo();
        var keyId = Base64UrlManual.Encode(SHA256.HashData(der))[..8];
        return (pem, ecdsa, keyId);
    }

    public static string BuildSignedHeaderValue(
        ECDsa privateKey,
        string keyId,
        string tenantId,
        string environmentId,
        string runId,
        string requestId,
        string method,
        string route,
        ReadOnlySpan<byte> body,
        long timestamp,
        long expiry,
        string? nonce = null,
        string alg = "ES256",
        string version = "1",
        byte[]? signatureOverride = null)
    {
        nonce ??= Base64UrlManual.Encode(RandomNumberGenerator.GetBytes(16));
        var bodyHash = ReplayCanonicalString.ComputeBodyHash(body);
        var canonical = ReplayCanonicalString.Build(
            alg, tenantId, environmentId, runId, requestId, method, route, bodyHash,
            timestamp.ToString(), expiry.ToString(), nonce);

        var signature = signatureOverride ?? privateKey.SignData(canonical, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        var sigEncoded = Base64UrlManual.Encode(signature);

        return $"v={version};alg={alg};kid={keyId};tid={tenantId};eid={environmentId};rid={runId};req={requestId};ts={timestamp};exp={expiry};n={nonce};sig={sigEncoded}";
    }
}

/// <summary>A <see cref="TimeProvider"/> whose "now" is set explicitly by the test, for deterministic
/// clock-skew/expiry assertions.</summary>
internal sealed class FixedTimeProvider : TimeProvider
{
    private DateTimeOffset _now;

    public FixedTimeProvider(DateTimeOffset now) => _now = now;

    public override DateTimeOffset GetUtcNow() => _now;

    public void Set(DateTimeOffset now) => _now = now;
}
