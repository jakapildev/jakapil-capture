using Jakapil.Capture.Replay;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Jakapil.Capture.Tests.Replay;

/// <summary>
/// Direct unit tests of <see cref="ReplayVerifier"/> against ADR-0003 §6.3's checklist (PLAN 15d-15-9): valid
/// signature accepted; expired, clock-skewed, replayed-nonce, tampered-body, unknown-alg, unknown-kid, and
/// scope-mismatched signatures all rejected — and REJECTION always means "ordinary traffic", never an
/// exception (INV-B3).
/// </summary>
public class ReplayVerifierTests
{
    private const string TenantId = "tenant-1";
    private const string EnvironmentId = "env-1";
    private static readonly DateTimeOffset BaseTime = new(2026, 7, 28, 12, 0, 0, TimeSpan.Zero);

    private sealed record Fixture(ReplayVerifier Verifier, FixedTimeProvider Clock, string KeyId, System.Security.Cryptography.ECDsa PrivateKey);

    private static Fixture BuildFixture(TimeSpan? clockSkewTolerance = null, int nonceCacheSize = 100)
    {
        var (pem, privateKey, keyId) = ReplayTestSigner.GenerateKeyPair();

        var options = new JakapilCaptureOptions
        {
            MaxInlineBodyBytes = 1024 * 1024,
            Replay = new ReplayVerificationOptions
            {
                PublicKeys = [pem],
                ExpectedTenantId = TenantId,
                ExpectedEnvironmentId = EnvironmentId,
                ClockSkewTolerance = clockSkewTolerance ?? TimeSpan.FromSeconds(300),
                NonceCacheSize = nonceCacheSize,
            },
        };

        var keyRing = new ReplayKeyRing([pem], NullLogger.Instance);
        var nonceCache = new ReplayNonceCache(nonceCacheSize);
        var clock = new FixedTimeProvider(BaseTime);
        var verifier = new ReplayVerifier(Microsoft.Extensions.Options.Options.Create(options), keyRing, nonceCache, clock, NullLogger<ReplayVerifier>.Instance);

        return new Fixture(verifier, clock, keyId, privateKey);
    }

    private static HttpContext BuildContext(string method, string route, byte[]? body, string? replayHeader)
    {
        var context = new DefaultHttpContext();
        context.Request.Method = method;

        var queryIndex = route.IndexOf('?');
        context.Request.Path = queryIndex >= 0 ? route[..queryIndex] : route;
        context.Request.QueryString = queryIndex >= 0 ? new QueryString(route[queryIndex..]) : QueryString.Empty;

        context.Request.Body = new MemoryStream(body ?? []);
        context.Request.ContentLength = body?.Length ?? 0;

        if (replayHeader is not null)
        {
            context.Request.Headers[ReplayProtocol.RequestHeaderName] = replayHeader;
        }

        return context;
    }

    private static string SignValid(Fixture fixture, string method, string route, byte[] body, string runId = "run-1", string requestId = "req-1", string? nonce = null, long? timestampOverride = null, long? expiryOverride = null)
    {
        var ts = timestampOverride ?? fixture.Clock.GetUtcNow().ToUnixTimeSeconds();
        var exp = expiryOverride ?? ts + 300;
        return ReplayTestSigner.BuildSignedHeaderValue(
            fixture.PrivateKey, fixture.KeyId, TenantId, EnvironmentId, runId, requestId,
            method, route, body, ts, exp, nonce);
    }

    [Fact]
    public async Task VerifyAsync_NoHeader_ReturnsFalse_NoBodyBufferingNeeded()
    {
        var fixture = BuildFixture();
        var context = BuildContext("GET", "/api/products/4", body: null, replayHeader: null);

        Assert.False(await fixture.Verifier.VerifyAsync(context));
    }

    [Fact]
    public async Task VerifyAsync_ValidSignature_ReturnsTrue()
    {
        var fixture = BuildFixture();
        var body = """{"name":"Widget"}"""u8.ToArray();
        var header = SignValid(fixture, "POST", "/api/products/4?x=1", body);
        var context = BuildContext("POST", "/api/products/4?x=1", body, header);

        Assert.True(await fixture.Verifier.VerifyAsync(context));
    }

    [Fact]
    public async Task VerifyAsync_ValidSignature_RequestBodyStillReadableAfterVerification()
    {
        var fixture = BuildFixture();
        var body = """{"name":"Widget"}"""u8.ToArray();
        var header = SignValid(fixture, "POST", "/api/products/4", body);
        var context = BuildContext("POST", "/api/products/4", body, header);

        await fixture.Verifier.VerifyAsync(context);

        using var reader = new StreamReader(context.Request.Body);
        var rewound = await reader.ReadToEndAsync();
        Assert.Equal("""{"name":"Widget"}""", rewound);
    }

    [Fact]
    public async Task VerifyAsync_TamperedBody_Rejected()
    {
        var fixture = BuildFixture();
        var signedBody = """{"amount":100}"""u8.ToArray();
        var header = SignValid(fixture, "POST", "/api/orders", signedBody);

        // The ACTUAL body received differs from what was signed (bodyHash is recomputed, never trusted from a
        // header field since there isn't one — but here we simulate a MITM/corruption scenario).
        var tamperedBody = """{"amount":999999}"""u8.ToArray();
        var context = BuildContext("POST", "/api/orders", tamperedBody, header);

        Assert.False(await fixture.Verifier.VerifyAsync(context));
    }

    [Fact]
    public async Task VerifyAsync_TamperedMethod_Rejected()
    {
        var fixture = BuildFixture();
        var body = "{}"u8.ToArray();
        var header = SignValid(fixture, "POST", "/api/orders", body);
        // Signature was computed for POST; the actual request is a DELETE.
        var context = BuildContext("DELETE", "/api/orders", body, header);

        Assert.False(await fixture.Verifier.VerifyAsync(context));
    }

    [Fact]
    public async Task VerifyAsync_TamperedRoute_Rejected()
    {
        var fixture = BuildFixture();
        var body = "{}"u8.ToArray();
        var header = SignValid(fixture, "GET", "/api/orders/1", body);
        var context = BuildContext("GET", "/api/orders/2", body, header);

        Assert.False(await fixture.Verifier.VerifyAsync(context));
    }

    [Fact]
    public async Task VerifyAsync_ExpiredSignature_Rejected()
    {
        var fixture = BuildFixture();
        var body = "{}"u8.ToArray();
        var now = fixture.Clock.GetUtcNow().ToUnixTimeSeconds();
        var header = SignValid(fixture, "GET", "/api/x", body, timestampOverride: now - 1000, expiryOverride: now - 500);
        var context = BuildContext("GET", "/api/x", body, header);

        Assert.False(await fixture.Verifier.VerifyAsync(context));
    }

    [Fact]
    public async Task VerifyAsync_TimestampOutsideClockSkewTolerance_Rejected()
    {
        var fixture = BuildFixture(clockSkewTolerance: TimeSpan.FromSeconds(30));
        var body = "{}"u8.ToArray();
        var now = fixture.Clock.GetUtcNow().ToUnixTimeSeconds();
        // ts is 1 hour in the future relative to "now" — outside a 30s tolerance — even though exp is still ahead.
        var header = SignValid(fixture, "GET", "/api/x", body, timestampOverride: now + 3600, expiryOverride: now + 3900);
        var context = BuildContext("GET", "/api/x", body, header);

        Assert.False(await fixture.Verifier.VerifyAsync(context));
    }

    [Fact]
    public async Task VerifyAsync_TimestampWithinClockSkewTolerance_Accepted()
    {
        var fixture = BuildFixture(clockSkewTolerance: TimeSpan.FromSeconds(300));
        var body = "{}"u8.ToArray();
        var now = fixture.Clock.GetUtcNow().ToUnixTimeSeconds();
        var header = SignValid(fixture, "GET", "/api/x", body, timestampOverride: now - 100, expiryOverride: now + 200);
        var context = BuildContext("GET", "/api/x", body, header);

        Assert.True(await fixture.Verifier.VerifyAsync(context));
    }

    [Fact]
    public async Task VerifyAsync_NonceReplayedWithinExpiry_SecondRequestRejected()
    {
        var fixture = BuildFixture();
        var body = "{}"u8.ToArray();
        var header = SignValid(fixture, "GET", "/api/x", body, nonce: "fixed-nonce-value");

        var firstContext = BuildContext("GET", "/api/x", body, header);
        Assert.True(await fixture.Verifier.VerifyAsync(firstContext));

        var secondContext = BuildContext("GET", "/api/x", body, header);
        Assert.False(await fixture.Verifier.VerifyAsync(secondContext));
    }

    [Fact]
    public async Task VerifyAsync_UnknownAlgorithm_Rejected()
    {
        var fixture = BuildFixture();
        var body = "{}"u8.ToArray();
        var header = SignValid(fixture, "GET", "/api/x", body);
        var withBadAlg = header.Replace("alg=ES256", "alg=EdDSA");
        var context = BuildContext("GET", "/api/x", body, withBadAlg);

        Assert.False(await fixture.Verifier.VerifyAsync(context));
    }

    [Fact]
    public async Task VerifyAsync_UnknownKeyId_Rejected()
    {
        var fixture = BuildFixture();
        var body = "{}"u8.ToArray();
        var header = SignValid(fixture, "GET", "/api/x", body);
        var withBadKid = header.Replace($"kid={fixture.KeyId}", "kid=ZZZZZZZZ");
        var context = BuildContext("GET", "/api/x", body, withBadKid);

        Assert.False(await fixture.Verifier.VerifyAsync(context));
    }

    [Fact]
    public async Task VerifyAsync_ExpectedTenantIdConfigured_TenantMismatch_Rejected()
    {
        var fixture = BuildFixture();
        var body = "{}"u8.ToArray();
        // Signed for a DIFFERENT tenant than this SDK instance's configured Replay.ExpectedTenantId.
        var header = ReplayTestSigner.BuildSignedHeaderValue(
            fixture.PrivateKey, fixture.KeyId, "some-other-tenant", EnvironmentId, "run-1", "req-1",
            "GET", "/api/x", body, fixture.Clock.GetUtcNow().ToUnixTimeSeconds(), fixture.Clock.GetUtcNow().ToUnixTimeSeconds() + 300);
        var context = BuildContext("GET", "/api/x", body, header);

        Assert.False(await fixture.Verifier.VerifyAsync(context));
    }

    [Fact]
    public async Task VerifyAsync_ExpectedEnvironmentIdConfigured_EnvironmentMismatch_Rejected()
    {
        var fixture = BuildFixture();
        var body = "{}"u8.ToArray();
        var header = ReplayTestSigner.BuildSignedHeaderValue(
            fixture.PrivateKey, fixture.KeyId, TenantId, "some-other-env", "run-1", "req-1",
            "GET", "/api/x", body, fixture.Clock.GetUtcNow().ToUnixTimeSeconds(), fixture.Clock.GetUtcNow().ToUnixTimeSeconds() + 300);
        var context = BuildContext("GET", "/api/x", body, header);

        Assert.False(await fixture.Verifier.VerifyAsync(context));
    }

    [Fact]
    public async Task VerifyAsync_ExpectedTenantIdNotConfigured_AnyTenantAccepted_CheckSkipped()
    {
        var (pem, privateKey, keyId) = ReplayTestSigner.GenerateKeyPair();
        var options = new JakapilCaptureOptions
        {
            // ExpectedTenantId left null — the check must be SKIPPED, not "always mismatch".
            Replay = new ReplayVerificationOptions { PublicKeys = [pem], ExpectedEnvironmentId = EnvironmentId },
        };
        var keyRing = new ReplayKeyRing([pem], NullLogger.Instance);
        var nonceCache = new ReplayNonceCache(10);
        var clock = new FixedTimeProvider(BaseTime);
        var verifier = new ReplayVerifier(Options.Create(options), keyRing, nonceCache, clock, NullLogger<ReplayVerifier>.Instance);

        var body = "{}"u8.ToArray();
        var now = BaseTime.ToUnixTimeSeconds();
        var header = ReplayTestSigner.BuildSignedHeaderValue(
            privateKey, keyId, "whatever-tenant-nobody-configured", EnvironmentId, "run-1", "req-1", "GET", "/x", body, now, now + 300);
        var context = BuildContext("GET", "/x", body, header);

        Assert.True(await verifier.VerifyAsync(context));
    }

    [Fact]
    public async Task VerifyAsync_ExpectedEnvironmentIdNotConfigured_AnyEnvironmentAccepted_CheckSkipped()
    {
        var (pem, privateKey, keyId) = ReplayTestSigner.GenerateKeyPair();
        var options = new JakapilCaptureOptions
        {
            // ExpectedEnvironmentId left null — the check must be SKIPPED, not "always mismatch". This is the
            // documented residual-risk case: a run signed for one environment verifies against any environment
            // sharing this key ring when only ExpectedEnvironmentId is left unconfigured.
            Replay = new ReplayVerificationOptions { PublicKeys = [pem], ExpectedTenantId = TenantId },
        };
        var keyRing = new ReplayKeyRing([pem], NullLogger.Instance);
        var nonceCache = new ReplayNonceCache(10);
        var clock = new FixedTimeProvider(BaseTime);
        var verifier = new ReplayVerifier(Options.Create(options), keyRing, nonceCache, clock, NullLogger<ReplayVerifier>.Instance);

        var body = "{}"u8.ToArray();
        var now = BaseTime.ToUnixTimeSeconds();
        var header = ReplayTestSigner.BuildSignedHeaderValue(
            privateKey, keyId, TenantId, "whatever-environment-nobody-configured", "run-1", "req-1", "GET", "/x", body, now, now + 300);
        var context = BuildContext("GET", "/x", body, header);

        Assert.True(await verifier.VerifyAsync(context));
    }

    [Fact]
    public async Task VerifyAsync_NeitherExpectedIdConfigured_AnySignerAccepted_CheckFullySkipped()
    {
        var (pem, privateKey, keyId) = ReplayTestSigner.GenerateKeyPair();
        var options = new JakapilCaptureOptions
        {
            Replay = new ReplayVerificationOptions { PublicKeys = [pem] },
        };
        var keyRing = new ReplayKeyRing([pem], NullLogger.Instance);
        var nonceCache = new ReplayNonceCache(10);
        var clock = new FixedTimeProvider(BaseTime);
        var verifier = new ReplayVerifier(Options.Create(options), keyRing, nonceCache, clock, NullLogger<ReplayVerifier>.Instance);

        var body = "{}"u8.ToArray();
        var now = BaseTime.ToUnixTimeSeconds();
        var header = ReplayTestSigner.BuildSignedHeaderValue(
            privateKey, keyId, "any-tenant", "any-env", "run-1", "req-1", "GET", "/x", body, now, now + 300);
        var context = BuildContext("GET", "/x", body, header);

        Assert.True(await verifier.VerifyAsync(context));
    }

    [Fact]
    public async Task VerifyAsync_MalformedHeaderValue_Rejected_NeverThrows()
    {
        var fixture = BuildFixture();
        var context = BuildContext("GET", "/api/x", body: null, replayHeader: "not-a-valid-header-at-all");

        var result = await fixture.Verifier.VerifyAsync(context);

        Assert.False(result);
    }

    [Fact]
    public async Task VerifyAsync_ReplayDisabledInOptions_AlwaysFalse_EvenWithValidSignature()
    {
        var (pem, privateKey, keyId) = ReplayTestSigner.GenerateKeyPair();
        var options = new JakapilCaptureOptions
        {
            Replay = new ReplayVerificationOptions { Enabled = false, PublicKeys = [pem], ExpectedTenantId = TenantId, ExpectedEnvironmentId = EnvironmentId },
        };
        var keyRing = new ReplayKeyRing([pem], NullLogger.Instance);
        var nonceCache = new ReplayNonceCache(10);
        var clock = new FixedTimeProvider(BaseTime);
        var verifier = new ReplayVerifier(Microsoft.Extensions.Options.Options.Create(options), keyRing, nonceCache, clock, NullLogger<ReplayVerifier>.Instance);

        var body = "{}"u8.ToArray();
        var header = ReplayTestSigner.BuildSignedHeaderValue(privateKey, keyId, TenantId, EnvironmentId, "r", "q", "GET", "/x", body, BaseTime.ToUnixTimeSeconds(), BaseTime.ToUnixTimeSeconds() + 300);
        var context = BuildContext("GET", "/x", body, header);

        Assert.False(await verifier.VerifyAsync(context));
    }

    [Fact]
    public async Task VerifyAsync_NoPublicKeysConfigured_AlwaysFalse_ZeroCostPath()
    {
        var options = new JakapilCaptureOptions
        {
            Replay = new ReplayVerificationOptions { PublicKeys = [], ExpectedTenantId = TenantId, ExpectedEnvironmentId = EnvironmentId },
        };
        var keyRing = new ReplayKeyRing([], NullLogger.Instance);
        var nonceCache = new ReplayNonceCache(10);
        var verifier = new ReplayVerifier(Microsoft.Extensions.Options.Options.Create(options), keyRing, nonceCache, new FixedTimeProvider(BaseTime), NullLogger<ReplayVerifier>.Instance);

        var context = BuildContext("GET", "/x", body: null, replayHeader: "v=1;alg=ES256;kid=x;tid=t;eid=e;rid=r;req=q;ts=1;exp=2;n=n;sig=s");

        Assert.False(await verifier.VerifyAsync(context));
    }
}
