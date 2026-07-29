using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using Jakapil.Capture;
using Jakapil.Capture.Anonymization;
using Jakapil.Capture.Contracts;
using Jakapil.Capture.Replay;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace Jakapil.Capture.Tests.Replay;

/// <summary>
/// End-to-end tests of ADR-0003's signed-replay path through the real ASP.NET Core pipeline (PLAN 15d-15-9):
/// valid signature masks the response and suppresses capture; invalid/missing signature behaves exactly like
/// today; <c>FlowFingerprint</c> leaves stay live in the masked response; the no-anonymization-key case is
/// well-defined (scheme=none, still suppressed).
/// </summary>
public class ReplayMiddlewareTests
{
    private const string TenantId = "11111111-1111-1111-1111-111111111111";
    private const string EnvironmentId = "22222222-2222-2222-2222-222222222222";
    private static readonly byte[] AnonKey = "test-anonymization-key-0123456789"u8.ToArray();

    private sealed class RecordingQueue : ICapturedInteractionQueue
    {
        public readonly List<CapturedInteraction> Captured = [];

        public ValueTask EnqueueAsync(CapturedInteraction interaction, CancellationToken ct = default)
        {
            Captured.Add(interaction);
            return ValueTask.CompletedTask;
        }

        public void Clear() => Captured.Clear();
    }

    private const string ResponseJson = """{"customerId":"cust-123","email":"jane@customer.example","password":"topsecret","price":9.99}""";

    private sealed record Env(TestServer Server, RecordingQueue Queue, ECDsa PrivateKey, string KeyId);

    private static Env BuildServer(bool withAnonymizationKey = true, int maxMaskedResponseBytes = 8 * 1024 * 1024)
    {
        var (pem, privateKey, keyId) = ReplayTestSigner.GenerateKeyPair();
        var queue = new RecordingQueue();

        var host = new HostBuilder()
            .ConfigureWebHost(webBuilder =>
            {
                webBuilder
                    .UseTestServer()
                    .ConfigureServices(services =>
                    {
                        services.Configure<JakapilCaptureOptions>(o =>
                        {
                            o.Replay.PublicKeys = [pem];
                            o.Replay.ExpectedTenantId = TenantId;
                            o.Replay.ExpectedEnvironmentId = EnvironmentId;
                            o.Replay.MaxMaskedResponseBytes = maxMaskedResponseBytes;
                        });
                        services.AddSingleton<ICapturedInteractionQueue>(queue);
                        services.AddSingleton<IAuthTokenRegistry, AuthTokenRegistry>();
                        services.AddSingleton<ICaptureRuntimeState>(new CaptureRuntimeState());
                        services.AddSingleton<IAnonymizer>(sp =>
                        {
                            var opts = sp.GetRequiredService<IOptions<JakapilCaptureOptions>>().Value;
                            return new Anonymizer(withAnonymizationKey ? AnonKey : null, opts.Anonymization, []);
                        });
                        services.AddSingleton<IReplayKeyRing, ReplayKeyRing>();
                        services.AddSingleton(sp => new ReplayNonceCache(sp.GetRequiredService<IOptions<JakapilCaptureOptions>>().Value.Replay.NonceCacheSize));
                        services.AddSingleton<IReplayVerifier, ReplayVerifier>();
                        services.TryAddSingleton(TimeProvider.System);
                        services.AddRouting();
                        services.AddLogging();
                    })
                    .Configure(app =>
                    {
                        app.UseRouting();
                        app.UseMiddleware<JakapilCaptureMiddleware>();
                        app.UseEndpoints(endpoints =>
                        {
                            endpoints.MapPost("/api/customers/{id}", async context =>
                            {
                                context.Response.ContentType = "application/json";
                                await context.Response.WriteAsync(ResponseJson);
                            });

                            endpoints.MapGet("/api/download", async context =>
                            {
                                context.Response.ContentType = "text/plain";
                                await context.Response.WriteAsync("just plain text, not JSON");
                            });

                            // v1.2.0 RunCredential (ADR-0003 §5 revision, WHY #1): a realistic login response —
                            // a run-issued token in the body plus a session cookie header — the exact shape the
                            // field bug report was built from.
                            endpoints.MapPost("/api/login", async context =>
                            {
                                context.Response.Headers.Append("Set-Cookie", "sessionId=live-session-abc; Path=/; HttpOnly");
                                context.Response.Headers.Location = "/api/sessions/live-session-abc";
                                context.Response.ContentType = "application/json";
                                await context.Response.WriteAsync("""{"token":"live-login-token-xyz","password":"unused-echo"}""");
                            });
                        });
                    });
            })
            .Start();

        return new Env(host.GetTestServer(), queue, privateKey, keyId);
    }

    private static async Task<HttpResponseMessage> SendSignedRequestAsync(
        Env env, HttpMethod method, string route, string? body, string? nonceOverride = null, string? algOverride = null, byte[]? bodyOverrideForSignature = null)
    {
        var bodyBytes = body is null ? [] : Encoding.UTF8.GetBytes(body);
        var signedOverBytes = bodyOverrideForSignature ?? bodyBytes;
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        var header = ReplayTestSigner.BuildSignedHeaderValue(
            env.PrivateKey, env.KeyId, TenantId, EnvironmentId, runId: "run-1", requestId: Guid.NewGuid().ToString("D"),
            method: method.Method, route: route, body: signedOverBytes, timestamp: now, expiry: now + 300,
            nonce: nonceOverride, alg: algOverride ?? "ES256");

        using var client = env.Server.CreateClient();
        using var request = new HttpRequestMessage(method, route);
        request.Headers.TryAddWithoutValidation(ReplayProtocol.RequestHeaderName, header);
        if (body is not null)
        {
            request.Content = new StringContent(body, Encoding.UTF8, "application/json");
        }

        return await client.SendAsync(request);
    }

    [Fact]
    public async Task ValidSignature_ResponseIsMasked_AndNotCaptured()
    {
        var env = BuildServer();

        var response = await SendSignedRequestAsync(env, HttpMethod.Post, "/api/customers/1", """{"noop":true}""");
        var body = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        // SyntheticPii (email) is transformed — never the raw value.
        Assert.DoesNotContain("jane@customer.example", body);
        // SecretTombstone (password) never appears in any form.
        Assert.DoesNotContain("topsecret", body);
        // SafeLiteral (price) passes through unchanged.
        Assert.Contains("9.99", body);

        Assert.Empty(env.Queue.Captured);
    }

    [Fact]
    public async Task ValidSignature_FlowFingerprintLeaf_StaysLivePlaintext_NotEnvelope()
    {
        var env = BuildServer();

        var response = await SendSignedRequestAsync(env, HttpMethod.Post, "/api/customers/1", """{"noop":true}""");
        var body = await response.Content.ReadAsStringAsync();

        // ADR-0003 §5: FlowFingerprint (customerId) is NOT masked in a signed-replay response — the runner's
        // binding chain needs the live value, not an fp: envelope.
        Assert.Contains("\"customerId\":\"cust-123\"", body);
        Assert.DoesNotContain("fp:", body);
    }

    [Fact]
    public async Task ValidSignature_SyntheticPii_IsDeterministic_SameRawValueAlwaysProducesSameSyntheticValue()
    {
        var env = BuildServer();

        var response1 = await SendSignedRequestAsync(env, HttpMethod.Post, "/api/customers/1", """{"noop":true}""");
        var body1 = await response1.Content.ReadAsStringAsync();

        var response2 = await SendSignedRequestAsync(env, HttpMethod.Post, "/api/customers/2", """{"noop":true}""");
        var body2 = await response2.Content.ReadAsStringAsync();

        // Same raw email ("jane@customer.example") on both responses -> same synthetic value both times
        // (ADR-0003 §3's determinism claim: this is what lets Equals-style assertions survive replay).
        var email1 = ExtractJsonStringField(body1, "email");
        var email2 = ExtractJsonStringField(body2, "email");
        Assert.Equal(email1, email2);
        Assert.NotEqual("jane@customer.example", email1);
    }

    [Fact]
    public async Task ValidSignature_SetsMaskingConfirmationHeader()
    {
        var env = BuildServer();

        var response = await SendSignedRequestAsync(env, HttpMethod.Post, "/api/customers/1", """{"noop":true}""");

        Assert.True(response.Headers.TryGetValues(ReplayProtocol.MaskedResponseHeaderName, out var values));
        var headerValue = Assert.Single(values!);
        Assert.StartsWith("v1;scheme=hmac-sha256-v1;keyVersion=", headerValue);
    }

    [Fact]
    public async Task NoHeader_BehavesExactlyLikeToday_ResponseUnmasked_Captured_NoConfirmationHeader()
    {
        var env = BuildServer();
        using var client = env.Server.CreateClient();

        var response = await client.PostAsync("/api/customers/1", new StringContent("""{"noop":true}""", Encoding.UTF8, "application/json"));
        var body = await response.Content.ReadAsStringAsync();

        Assert.Equal(ResponseJson, body);
        Assert.False(response.Headers.Contains(ReplayProtocol.MaskedResponseHeaderName));
        Assert.Single(env.Queue.Captured);
    }

    [Fact]
    public async Task TamperedBody_TreatedAsOrdinaryTraffic_NotMasked_StillCaptured()
    {
        var env = BuildServer();

        // Sign for one body, physically send a different one.
        var response = await SendSignedRequestAsync(
            env, HttpMethod.Post, "/api/customers/1", body: """{"real":true}""",
            bodyOverrideForSignature: """{"signed-for":"something-else"}"""u8.ToArray());
        var body = await response.Content.ReadAsStringAsync();

        Assert.Equal(ResponseJson, body); // unmasked
        Assert.False(response.Headers.Contains(ReplayProtocol.MaskedResponseHeaderName));
        Assert.Single(env.Queue.Captured); // ordinary capture still happens
    }

    [Fact]
    public async Task ExpiredSignature_TreatedAsOrdinaryTraffic()
    {
        var env = BuildServer();
        var bodyBytes = Encoding.UTF8.GetBytes("""{"noop":true}""");
        var expiredHeader = ReplayTestSigner.BuildSignedHeaderValue(
            env.PrivateKey, env.KeyId, TenantId, EnvironmentId, "run-1", "req-1",
            "POST", "/api/customers/1", bodyBytes, timestamp: 1000, expiry: 1300);

        using var client = env.Server.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/customers/1")
        {
            Content = new StringContent("""{"noop":true}""", Encoding.UTF8, "application/json"),
        };
        request.Headers.TryAddWithoutValidation(ReplayProtocol.RequestHeaderName, expiredHeader);

        var response = await client.SendAsync(request);
        var body = await response.Content.ReadAsStringAsync();

        Assert.Equal(ResponseJson, body);
        Assert.False(response.Headers.Contains(ReplayProtocol.MaskedResponseHeaderName));
        Assert.Single(env.Queue.Captured);
    }

    [Fact]
    public async Task NonceReplayed_SecondRequestTreatedAsOrdinaryTraffic()
    {
        var env = BuildServer();
        const string nonce = "fixed-nonce-for-replay-test";

        var first = await SendSignedRequestAsync(env, HttpMethod.Post, "/api/customers/1", """{"noop":true}""", nonceOverride: nonce);
        Assert.Empty(env.Queue.Captured); // first: valid, suppressed

        var second = await SendSignedRequestAsync(env, HttpMethod.Post, "/api/customers/1", """{"noop":true}""", nonceOverride: nonce);
        var secondBody = await second.Content.ReadAsStringAsync();

        Assert.Equal(ResponseJson, secondBody); // second: replay rejected -> unmasked
        Assert.Single(env.Queue.Captured); // and captured normally, like ordinary traffic
    }

    [Fact]
    public async Task UnknownAlgorithm_TreatedAsOrdinaryTraffic()
    {
        var env = BuildServer();

        var response = await SendSignedRequestAsync(env, HttpMethod.Post, "/api/customers/1", """{"noop":true}""", algOverride: "EdDSA");
        var body = await response.Content.ReadAsStringAsync();

        Assert.Equal(ResponseJson, body);
        Assert.Single(env.Queue.Captured);
    }

    [Fact]
    public async Task NoAnonymizationKeyConfigured_SignatureStillVerifies_CaptureSuppressed_BodyUnmasked_SchemeNone()
    {
        var env = BuildServer(withAnonymizationKey: false);

        var response = await SendSignedRequestAsync(env, HttpMethod.Post, "/api/customers/1", """{"noop":true}""");
        var body = await response.Content.ReadAsStringAsync();

        // ADR-0003 §8.4: capture suppression still works even with no key, but there is nothing to mask WITH.
        Assert.Equal(ResponseJson, body);
        Assert.Empty(env.Queue.Captured);

        Assert.True(response.Headers.TryGetValues(ReplayProtocol.MaskedResponseHeaderName, out var values));
        Assert.Equal("v1;scheme=none;keyVersion=1", Assert.Single(values!));
    }

    [Fact]
    public async Task NonJsonResponse_CannotBeMasked_SentThroughUnmodified_ConfirmationHeaderDeclaresUnmaskedNonJson_StillSuppressed()
    {
        var env = BuildServer();
        var bodyBytes = Array.Empty<byte>();
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var header = ReplayTestSigner.BuildSignedHeaderValue(
            env.PrivateKey, env.KeyId, TenantId, EnvironmentId, "run-1", "req-1",
            "GET", "/api/download", bodyBytes, now, now + 300);

        using var client = env.Server.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Get, "/api/download");
        request.Headers.TryAddWithoutValidation(ReplayProtocol.RequestHeaderName, header);

        var response = await client.SendAsync(request);
        var body = await response.Content.ReadAsStringAsync();

        Assert.Equal("just plain text, not JSON", body);

        // ADR-0003 §5 revision, "non-JSON pass-through": a non-JSON body can't be masked, but that fact is now
        // reported honestly via body=unmasked-nonjson instead of omitting the header entirely (the original
        // bug this revision fixes — see Jakapil.Capture.Tests.Replay.ReplayMaskedHeaderMatrixTests for the full
        // matrix). The full response matrix lives there; this test just keeps this specific end-to-end
        // scenario (through the real ASP.NET Core pipeline, alongside this file's other replay tests) covered.
        Assert.True(response.Headers.TryGetValues(ReplayProtocol.MaskedResponseHeaderName, out var values));
        var headerValue = Assert.Single(values!);
        Assert.Contains($";body={ReplayProtocol.UnmaskedNonJsonBodyDisposition}", headerValue);

        // Capture suppression is unconditional on a valid signature, independent of maskability.
        Assert.Empty(env.Queue.Captured);
    }

    // ---- v1.2.0 RunCredential — end-to-end through the real pipeline (ADR-0003 §5 revision, WHY #1) -----------

    [Fact]
    public async Task ValidSignature_LoginResponse_TokenPassesLive_PasswordStaysTombstoned_CookieAndLocationPassLive()
    {
        var env = BuildServer();

        var response = await SendSignedRequestAsync(env, HttpMethod.Post, "/api/login", """{"noop":true}""");
        var body = await response.Content.ReadAsStringAsync();

        // The exact reported defect: a token field is USABLE by the Runner (live), not a dead tombstone marker.
        Assert.Contains("\"token\":\"live-login-token-xyz\"", body);
        Assert.DoesNotContain("jkp:tomb:s:token", body);

        // password is an input secret, never a run artifact — stays tombstoned even in the same response.
        Assert.Contains("jkp:tomb:s:password", body);
        Assert.DoesNotContain("unused-echo", body);

        // Set-Cookie / Location respond with their live values, unmodified — the Runner needs the real cookie
        // and the real created-resource location to chain the next step.
        Assert.True(response.Headers.TryGetValues("Set-Cookie", out var cookieValues));
        Assert.Contains("live-session-abc", Assert.Single(cookieValues!));
        Assert.Equal("/api/sessions/live-session-abc", response.Headers.Location?.ToString());

        Assert.Empty(env.Queue.Captured);
    }

    [Fact]
    public async Task ValidSignature_LoginResponse_MaskingConfirmationHeader_DeclaresTokenLeafAndBothHeaders()
    {
        var env = BuildServer();

        var response = await SendSignedRequestAsync(env, HttpMethod.Post, "/api/login", """{"noop":true}""");

        Assert.True(response.Headers.TryGetValues(ReplayProtocol.MaskedResponseHeaderName, out var values));
        var headerValue = Assert.Single(values!);

        Assert.StartsWith("v1;scheme=hmac-sha256-v1;keyVersion=", headerValue);
        Assert.Contains(";live=$.token", headerValue);
        Assert.Contains(";liveHeaders=", headerValue);

        // Parse it back exactly the way the grammar documentation (JakapilCaptureMiddleware.SetMaskedHeader)
        // says the Jakapil side should: split on ';', then on '=' for each key/value token.
        var fields = headerValue.Split(';').Select(part =>
        {
            var eq = part.IndexOf('=');
            return eq < 0 ? (Key: part, Value: string.Empty) : (Key: part[..eq], Value: part[(eq + 1)..]);
        }).ToDictionary(p => p.Key, p => p.Value);

        Assert.Equal("hmac-sha256-v1", fields["scheme"]);
        var livePaths = fields["live"].Split(',');
        Assert.Equal(["$.token"], livePaths);

        var liveHeaders = fields["liveHeaders"].Split(',').OrderBy(h => h, StringComparer.Ordinal).ToArray();
        Assert.Equal(["Location", "Set-Cookie"], liveHeaders);
    }

    [Fact]
    public async Task ValidSignature_NoRunCredentialLeaves_MaskingConfirmationHeader_OmitsLiveFields()
    {
        // Regression: the pre-v1.2.0 response shape (no token/session/cookie/csrf/cursor field, no Set-Cookie/
        // Location header) must produce EXACTLY the old header format — no empty `live=`/`liveHeaders=` clutter.
        var env = BuildServer();

        var response = await SendSignedRequestAsync(env, HttpMethod.Post, "/api/customers/1", """{"noop":true}""");

        Assert.True(response.Headers.TryGetValues(ReplayProtocol.MaskedResponseHeaderName, out var values));
        var headerValue = Assert.Single(values!);

        Assert.Matches(@"^v1;scheme=hmac-sha256-v1;keyVersion=\d+$", headerValue);
    }

    private static string ExtractJsonStringField(string json, string fieldName)
    {
        using var document = System.Text.Json.JsonDocument.Parse(json);
        return document.RootElement.GetProperty(fieldName).GetString()!;
    }
}
