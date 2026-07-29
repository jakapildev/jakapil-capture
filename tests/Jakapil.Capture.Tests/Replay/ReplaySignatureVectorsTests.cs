using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Jakapil.Capture.Anonymization;
using Jakapil.Capture.Replay;

namespace Jakapil.Capture.Tests.Replay;

/// <summary>
/// Cross-implementation contract test: <c>tests/vectors/replay-signature-vectors.json</c> is the golden fixture
/// the Jakapil (server/Runner) side is expected to consume verbatim to prove its OWN independent canonical-string
/// builder produces byte-identical output to this SDK's (ADR-0003 §6.2 is explicitly marked binding — one
/// character of drift invalidates every signature in the field). This test protects the fixture FROM this repo's
/// side: it recomputes every case's canonical string / body hash from the file's own recorded inputs using the
/// SAME production code the middleware uses, and asserts the result matches what is recorded — so the file can
/// never silently drift from <see cref="ReplayCanonicalString"/>'s actual behavior. It also verifies each
/// recorded signature is genuinely valid (round-tripped through real ECDSA verification, not just copied bytes)
/// and that the recorded <c>replayHeaderValue</c> parses back to the same field values via
/// <see cref="ReplayHeader.TryParse"/>.
/// </summary>
public class ReplaySignatureVectorsTests
{
    private sealed record VectorsFile(TestKeyPair TestKeyPair, List<VectorCase> Cases);

    private sealed record TestKeyPair(string KeyId, string PublicKeySpkiPem, string PrivateKeyPkcs8Pem);

    private sealed record VectorCase(
        string Name, string Description, string Alg, string KeyId, string TenantId, string EnvironmentId,
        string RunId, string RequestId, string Method, string Route, string BodyBase64, string BodyHash,
        long Timestamp, long Expiry, string Nonce, string CanonicalString, string SignatureBase64Url,
        string ReplayHeaderValue);

    private static VectorsFile LoadVectorsFile([CallerFilePath] string sourceFilePath = "")
    {
        // sourceFilePath: .../tests/Jakapil.Capture.Tests/Replay/ReplaySignatureVectorsTests.cs
        // Two levels up (Replay -> Jakapil.Capture.Tests -> tests) reaches the repo's "tests" directory.
        var testsDir = Path.GetFullPath(Path.Combine(Path.GetDirectoryName(sourceFilePath)!, "..", ".."));
        var path = Path.Combine(testsDir, "vectors", "replay-signature-vectors.json");

        var json = File.ReadAllText(path);
        var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
        return JsonSerializer.Deserialize<VectorsFile>(json, options)
            ?? throw new InvalidOperationException($"Failed to deserialize {path}");
    }

    public static IEnumerable<object[]> Cases()
    {
        foreach (var c in LoadVectorsFile().Cases)
        {
            yield return [c.Name];
        }
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public void RecomputedBodyHash_MatchesRecordedValue(string caseName)
    {
        var file = LoadVectorsFile();
        var c = file.Cases.Single(x => x.Name == caseName);

        var bodyBytes = Convert.FromBase64String(c.BodyBase64);
        var recomputedHash = ReplayCanonicalString.ComputeBodyHash(bodyBytes);

        Assert.Equal(c.BodyHash, recomputedHash);
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public void RecomputedCanonicalString_MatchesRecordedValue_ByteForByte(string caseName)
    {
        var file = LoadVectorsFile();
        var c = file.Cases.Single(x => x.Name == caseName);

        var bodyBytes = Convert.FromBase64String(c.BodyBase64);
        var bodyHash = ReplayCanonicalString.ComputeBodyHash(bodyBytes);

        var recomputedBytes = ReplayCanonicalString.Build(
            c.Alg, c.TenantId, c.EnvironmentId, c.RunId, c.RequestId,
            c.Method, c.Route, bodyHash, c.Timestamp.ToString(), c.Expiry.ToString(), c.Nonce);
        var recomputedString = Encoding.UTF8.GetString(recomputedBytes);

        Assert.Equal(c.CanonicalString, recomputedString);
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public void RecordedSignature_IsGenuinelyValid_OverTheRecomputedCanonicalString(string caseName)
    {
        var file = LoadVectorsFile();
        var c = file.Cases.Single(x => x.Name == caseName);

        using var publicKey = ECDsa.Create();
        publicKey.ImportFromPem(file.TestKeyPair.PublicKeySpkiPem);

        var bodyBytes = Convert.FromBase64String(c.BodyBase64);
        var bodyHash = ReplayCanonicalString.ComputeBodyHash(bodyBytes);
        var canonicalBytes = ReplayCanonicalString.Build(
            c.Alg, c.TenantId, c.EnvironmentId, c.RunId, c.RequestId,
            c.Method, c.Route, bodyHash, c.Timestamp.ToString(), c.Expiry.ToString(), c.Nonce);

        var signatureBytes = Base64UrlManual.Decode(c.SignatureBase64Url);

        var valid = publicKey.VerifyData(canonicalBytes, signatureBytes, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

        Assert.True(valid, $"Recorded signature for case '{caseName}' does not verify against the recomputed canonical string.");
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public void RecordedKeyId_MatchesDerivedKeyIdFromThePublicKey(string caseName)
    {
        var file = LoadVectorsFile();
        var c = file.Cases.Single(x => x.Name == caseName);

        using var publicKey = ECDsa.Create();
        publicKey.ImportFromPem(file.TestKeyPair.PublicKeySpkiPem);
        var der = publicKey.ExportSubjectPublicKeyInfo();
        var derivedKeyId = Base64UrlManual.Encode(SHA256.HashData(der))[..8];

        Assert.Equal(file.TestKeyPair.KeyId, derivedKeyId);
        Assert.Equal(file.TestKeyPair.KeyId, c.KeyId);
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public void RecordedReplayHeaderValue_ParsesBackToTheSameFieldValues(string caseName)
    {
        var file = LoadVectorsFile();
        var c = file.Cases.Single(x => x.Name == caseName);

        var header = ReplayHeader.TryParse(c.ReplayHeaderValue);

        Assert.NotNull(header);
        Assert.Equal("1", header!.Version);
        Assert.Equal(c.Alg, header.Alg);
        Assert.Equal(c.KeyId, header.KeyId);
        Assert.Equal(c.TenantId, header.TenantId);
        Assert.Equal(c.EnvironmentId, header.EnvironmentId);
        Assert.Equal(c.RunId, header.RunId);
        Assert.Equal(c.RequestId, header.RequestId);
        Assert.Equal(c.Timestamp.ToString(), header.Timestamp);
        Assert.Equal(c.Expiry.ToString(), header.Expiry);
        Assert.Equal(c.Nonce, header.Nonce);
        Assert.Equal(c.SignatureBase64Url, header.Signature);
    }

    [Fact]
    public void VectorsFile_CoversTheRequiredCaseShapes()
    {
        var file = LoadVectorsFile();
        var names = file.Cases.Select(c => c.Name).ToList();

        Assert.Contains("get-empty-body", names);
        Assert.Contains("post-with-body", names);
        Assert.Contains(names, n => n.Contains("non-ascii", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(names, n => n.Contains("percent-encoded", StringComparison.OrdinalIgnoreCase));

        // At least one case must carry a real signature the file's public key verifies — the whole point is
        // giving the other side an end-to-end check, not just canonical-string string-comparison.
        Assert.Contains(file.Cases, c => !string.IsNullOrEmpty(c.SignatureBase64Url));
    }
}
