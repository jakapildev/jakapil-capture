using System.Text;
using Jakapil.Capture.Replay;

namespace Jakapil.Capture.Tests.Replay;

/// <summary>
/// ADR-0003 §6.2 is marked byte-for-byte binding: the Jakapil Runner builds the identical canonical string
/// independently. These tests pin the EXACT format (field order, single-LF separator, no trailing LF, UTF-8) so
/// any accidental drift in <see cref="ReplayCanonicalString"/> is caught immediately.
/// </summary>
public class ReplayCanonicalStringTests
{
    [Fact]
    public void Build_ProducesExactAdr0003Format_FieldOrderAndLfSeparatedNoTrailingNewline()
    {
        var bytes = ReplayCanonicalString.Build(
            alg: "ES256",
            tenantId: "11111111-1111-1111-1111-111111111111",
            environmentId: "22222222-2222-2222-2222-222222222222",
            runId: "33333333-3333-3333-3333-333333333333",
            requestId: "44444444-4444-4444-4444-444444444444",
            method: "POST",
            route: "/api/products/4?x=1",
            bodyHashBase64Url: "abc123",
            timestamp: "1700000000",
            expiry: "1700000300",
            nonce: "nonceValue");

        var expected = string.Join(
            '\n',
            "jakapil-replay-v1",
            "ES256",
            "11111111-1111-1111-1111-111111111111",
            "22222222-2222-2222-2222-222222222222",
            "33333333-3333-3333-3333-333333333333",
            "44444444-4444-4444-4444-444444444444",
            "POST",
            "/api/products/4?x=1",
            "abc123",
            "1700000000",
            "1700000300",
            "nonceValue");

        Assert.Equal(expected, Encoding.UTF8.GetString(bytes));
        Assert.False(Encoding.UTF8.GetString(bytes).EndsWith('\n'));
    }

    [Fact]
    public void ComputeBodyHash_EmptyBody_NeverOmitted_HashesTheEmptyByteArray()
    {
        var hash = ReplayCanonicalString.ComputeBodyHash(ReadOnlySpan<byte>.Empty);

        // SHA-256 of the empty byte array, base64url-encoded (well-known constant:
        // e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85).
        var expectedSha256Empty = System.Security.Cryptography.SHA256.HashData(ReadOnlySpan<byte>.Empty);
        var expectedBase64Url = Convert.ToBase64String(expectedSha256Empty).Replace('+', '-').Replace('/', '_').TrimEnd('=');

        Assert.False(string.IsNullOrEmpty(hash));
        Assert.Equal(expectedBase64Url, hash);
        Assert.Equal("47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU", hash);
    }

    [Fact]
    public void ComputeBodyHash_IsDeterministic_SameBytesProduceSameHash()
    {
        var bytes = "{\"a\":1}"u8.ToArray();

        var hash1 = ReplayCanonicalString.ComputeBodyHash(bytes);
        var hash2 = ReplayCanonicalString.ComputeBodyHash(bytes);

        Assert.Equal(hash1, hash2);
    }

    [Fact]
    public void ComputeBodyHash_DifferentBytes_ProduceDifferentHash()
    {
        var hashA = ReplayCanonicalString.ComputeBodyHash("A"u8);
        var hashB = ReplayCanonicalString.ComputeBodyHash("B"u8);

        Assert.NotEqual(hashA, hashB);
    }

    [Fact]
    public void ComputeBodyHash_NeverContainsPaddingOrUrlUnsafeCharacters()
    {
        var hash = ReplayCanonicalString.ComputeBodyHash("some request body"u8);

        Assert.DoesNotContain('=', hash);
        Assert.DoesNotContain('+', hash);
        Assert.DoesNotContain('/', hash);
    }
}
