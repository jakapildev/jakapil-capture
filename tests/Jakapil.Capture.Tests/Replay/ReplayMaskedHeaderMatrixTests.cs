using System.Text;
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
/// The full regression matrix for the ADR-0003 masking-confirmation header (<c>X-Jakapil-Masked</c>) across
/// every response-body shape the signed-replay path can produce: JSON (well-formed and malformed), non-JSON
/// content types, empty bodies, unmatched routes, truncated bodies, and exception paths. This matrix is what
/// caught the original bug this test file exists to guard against — a non-JSON response body (e.g. a
/// <c>409 text/plain</c>) got NO confirmation header at all, because <see cref="Anonymizer.MaskReplayResponseBody"/>
/// returns <c>null</c> for a non-JSON content type and <see cref="JakapilCaptureMiddleware.FinalizeReplayResponseAsync"/>
/// used to treat every <c>null</c> the same way (no header). The fix (ADR-0003 §5 revision, "non-JSON
/// pass-through") distinguishes that case from a genuinely malformed JSON body — see
/// <see cref="IAnonymizer.IsReplayResponseBodyJson"/> — and reports it honestly via the header's new
/// <c>body=unmasked-nonjson</c> field instead of staying silent.
/// </summary>
public class ReplayMaskedHeaderMatrixTests
{
    private const string TenantId = "11111111-1111-1111-1111-111111111111";
    private const string EnvironmentId = "22222222-2222-2222-2222-222222222222";
    private static readonly byte[] AnonKey = "test-anonymization-key-0123456789"u8.ToArray();

    private sealed class RecordingQueue : ICapturedInteractionQueue
    {
        public ValueTask EnqueueAsync(CapturedInteraction interaction, CancellationToken ct = default) => ValueTask.CompletedTask;

        public void Clear()
        {
        }
    }

    private sealed record Env(TestServer Server, System.Security.Cryptography.ECDsa PrivateKey, string KeyId);

    /// <summary>Builds a replay-enabled pipeline (same skeleton as <c>ReplayMiddlewareTests.BuildServer</c>) with
    /// the diagnostic endpoints this matrix exercises: every response-body shape that determines the
    /// confirmation header's disposition. <paramref name="maxMaskedResponseBytes"/> defaults to a large value
    /// (never truncates) and is only lowered by the truncation case, to force
    /// <see cref="ReplayMaskingResponseStream.Truncated"/> without needing a huge response body.</summary>
    private static Env BuildServer(int maxMaskedResponseBytes = 8 * 1024 * 1024)
    {
        var (pem, privateKey, keyId) = ReplayTestSigner.GenerateKeyPair();

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
                        services.AddSingleton<ICapturedInteractionQueue>(new RecordingQueue());
                        services.AddSingleton<IAuthTokenRegistry, AuthTokenRegistry>();
                        services.AddSingleton<ICaptureRuntimeState>(new CaptureRuntimeState());
                        services.AddSingleton<IAnonymizer>(sp =>
                        {
                            var opts = sp.GetRequiredService<IOptions<JakapilCaptureOptions>>().Value;
                            return new Anonymizer(AnonKey, opts.Anonymization, []);
                        });
                        services.AddSingleton<IReplayKeyRing, ReplayKeyRing>();
                        services.AddSingleton(sp => new ReplayNonceCache(sp.GetRequiredService<IOptions<JakapilCaptureOptions>>().Value.Replay.NonceCacheSize));
                        services.AddSingleton<IReplayVerifier, ReplayVerifier>();
                        services.TryAddSingleton(TimeProvider.System);
                        services.AddRouting();
                    })
                    .Configure(app =>
                    {
                        app.UseRouting();
                        app.UseMiddleware<JakapilCaptureMiddleware>();
                        app.UseEndpoints(endpoints =>
                        {
                            endpoints.MapPost("/diag/200-json", async context =>
                            {
                                context.Response.StatusCode = 200;
                                context.Response.ContentType = "application/json";
                                await context.Response.WriteAsync("""{"ok":true}""");
                            });

                            endpoints.MapPost("/diag/409-json", async context =>
                            {
                                context.Response.StatusCode = 409;
                                context.Response.ContentType = "application/json";
                                await context.Response.WriteAsync("""{"error":"conflict"}""");
                            });

                            endpoints.MapPost("/diag/409-text", async context =>
                            {
                                context.Response.StatusCode = 409;
                                context.Response.ContentType = "text/plain";
                                await context.Response.WriteAsync("conflict: duplicate resource");
                            });

                            endpoints.MapPost("/diag/409-problemjson", async context =>
                            {
                                context.Response.StatusCode = 409;
                                context.Response.ContentType = "application/problem+json";
                                await context.Response.WriteAsync("""{"type":"about:blank","title":"Conflict","status":409}""");
                            });

                            endpoints.MapPost("/diag/400-empty", context =>
                            {
                                context.Response.StatusCode = 400;
                                return Task.CompletedTask;
                            });

                            endpoints.MapPost("/diag/409-malformed-json", async context =>
                            {
                                // Content-Type CLAIMS json but the body is not well-formed JSON — this must be
                                // treated differently from a genuinely non-JSON content type (Case3 above): it
                                // is a fail-closed case, not a pass-through one (see
                                // JakapilCaptureMiddleware.FinalizeReplayResponseAsync's malformed-JSON comment).
                                context.Response.StatusCode = 409;
                                context.Response.ContentType = "application/json";
                                await context.Response.WriteAsync("{not valid json");
                            });

                            endpoints.MapPost("/diag/large-text", async context =>
                            {
                                // Used only by the truncation case (small MaxMaskedResponseBytes) — a body long
                                // enough to exceed any reasonable truncation threshold below.
                                context.Response.StatusCode = 200;
                                context.Response.ContentType = "text/plain";
                                await context.Response.WriteAsync(new string('x', 200));
                            });
                        });
                    });
            })
            .Start();

        return new Env(host.GetTestServer(), privateKey, keyId);
    }

    /// <summary>Cases 7/8: an outer (registered BEFORE <c>JakapilCaptureMiddleware</c>) exception-handler
    /// pipeline, same pattern as <c>JakapilCaptureMiddlewareTests.BuildOuterExceptionServer</c>, plus replay
    /// signature verification turned on.</summary>
    private static Env BuildOuterExceptionServer(bool withOuterHandler)
    {
        var (pem, privateKey, keyId) = ReplayTestSigner.GenerateKeyPair();

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
                        });
                        services.AddSingleton<ICapturedInteractionQueue>(new RecordingQueue());
                        services.AddSingleton<IAuthTokenRegistry, AuthTokenRegistry>();
                        services.AddSingleton<ICaptureRuntimeState>(new CaptureRuntimeState());
                        services.AddSingleton<IAnonymizer>(sp =>
                        {
                            var opts = sp.GetRequiredService<IOptions<JakapilCaptureOptions>>().Value;
                            return new Anonymizer(AnonKey, opts.Anonymization, []);
                        });
                        services.AddSingleton<IReplayKeyRing, ReplayKeyRing>();
                        services.AddSingleton(sp => new ReplayNonceCache(sp.GetRequiredService<IOptions<JakapilCaptureOptions>>().Value.Replay.NonceCacheSize));
                        services.AddSingleton<IReplayVerifier, ReplayVerifier>();
                        services.TryAddSingleton(TimeProvider.System);
                        services.AddRouting();
                    })
                    .Configure(app =>
                    {
                        if (withOuterHandler)
                        {
                            // Registered BEFORE JakapilCaptureMiddleware, so its 500 write is still visible to
                            // the replay masking stream via the OnCompleted deferral.
                            app.Use(async (context, next) =>
                            {
                                try
                                {
                                    await next(context);
                                }
                                catch (InvalidOperationException ex)
                                {
                                    context.Response.StatusCode = 500;
                                    context.Response.ContentType = "application/problem+json";
                                    await context.Response.WriteAsync($$"""{"type":"about:blank","title":"Internal Server Error","detail":"{{ex.Message}}"}""");
                                }
                            });
                        }

                        app.UseRouting();
                        app.UseMiddleware<JakapilCaptureMiddleware>();
                        app.UseEndpoints(endpoints =>
                        {
                            endpoints.MapPost("/diag/exception", context =>
                                throw new InvalidOperationException("boom"));
                        });
                    });
            })
            .Start();

        return new Env(host.GetTestServer(), privateKey, keyId);
    }

    private static async Task<HttpResponseMessage> SendSignedRequestAsync(
        Env env, HttpMethod method, string route, string? body)
    {
        var bodyBytes = body is null ? [] : Encoding.UTF8.GetBytes(body);
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        var header = ReplayTestSigner.BuildSignedHeaderValue(
            env.PrivateKey, env.KeyId, TenantId, EnvironmentId, runId: "run-1", requestId: Guid.NewGuid().ToString("D"),
            method: method.Method, route: route, body: bodyBytes, timestamp: now, expiry: now + 300);

        using var client = env.Server.CreateClient();
        using var request = new HttpRequestMessage(method, route);
        request.Headers.TryAddWithoutValidation(ReplayProtocol.RequestHeaderName, header);
        if (body is not null)
        {
            request.Content = new StringContent(body, Encoding.UTF8, "application/json");
        }

        return await client.SendAsync(request);
    }

    /// <summary>Extracts the single <c>X-Jakapil-Masked</c> header value, or <c>null</c> if the header is absent
    /// (there is never more than one value — <see cref="JakapilCaptureMiddleware.SetMaskedHeader"/> always
    /// assigns, never appends).</summary>
    private static string? MaskedHeaderValue(HttpResponseMessage response) =>
        response.Headers.TryGetValues(ReplayProtocol.MaskedResponseHeaderName, out var values) ? Assert.Single(values) : null;

    [Fact]
    public async Task Case1_200_Json_HeaderPresent_NoBodyField()
    {
        var env = BuildServer();
        var response = await SendSignedRequestAsync(env, HttpMethod.Post, "/diag/200-json", """{"noop":true}""");

        var headerValue = MaskedHeaderValue(response);
        Assert.NotNull(headerValue);
        Assert.StartsWith("v1;scheme=hmac-sha256-v1;keyVersion=", headerValue);
        Assert.DoesNotContain(";body=", headerValue);
    }

    [Fact]
    public async Task Case2_409_Json_HeaderPresent_NoBodyField()
    {
        var env = BuildServer();
        var response = await SendSignedRequestAsync(env, HttpMethod.Post, "/diag/409-json", """{"noop":true}""");

        var headerValue = MaskedHeaderValue(response);
        Assert.NotNull(headerValue);
        Assert.DoesNotContain(";body=", headerValue);
    }

    /// <summary>The bug this file exists to catch: before the fix, a non-JSON replay response body got NO
    /// confirmation header at all. Now it must get the header, honestly declaring the body was forwarded
    /// unmasked, AND the body itself must be byte-identical to what the endpoint wrote (true pass-through, not
    /// an opaque masked blob).</summary>
    [Fact]
    public async Task Case3_409_TextPlain_HeaderPresent_WithUnmaskedNonJsonBodyField_BodyByteIdentical()
    {
        var env = BuildServer();
        var response = await SendSignedRequestAsync(env, HttpMethod.Post, "/diag/409-text", """{"noop":true}""");

        var headerValue = MaskedHeaderValue(response);
        Assert.NotNull(headerValue);
        Assert.StartsWith($"v1;scheme=hmac-sha256-v1;keyVersion=", headerValue);
        Assert.Contains($";body={ReplayProtocol.UnmaskedNonJsonBodyDisposition}", headerValue);

        var bodyBytes = await response.Content.ReadAsByteArrayAsync();
        Assert.Equal("conflict: duplicate resource"u8.ToArray(), bodyBytes);
    }

    [Fact]
    public async Task Case4_409_ProblemJson_HeaderPresent_NoBodyField()
    {
        var env = BuildServer();
        // application/problem+json contains "json" — still treated as JSON masking-wise, so this is the
        // ordinary masked path, not the non-JSON pass-through one.
        var response = await SendSignedRequestAsync(env, HttpMethod.Post, "/diag/409-problemjson", """{"noop":true}""");

        var headerValue = MaskedHeaderValue(response);
        Assert.NotNull(headerValue);
        Assert.DoesNotContain(";body=", headerValue);
    }

    [Fact]
    public async Task Case5_400_NoBody_HeaderPresent_NoBodyField()
    {
        var env = BuildServer();
        // An empty body is trivially "masked" (MaskReplayResponseBody's own bodyBytes.Length == 0 early
        // return) regardless of Content-Type — it must NOT take the non-JSON pass-through branch.
        var response = await SendSignedRequestAsync(env, HttpMethod.Post, "/diag/400-empty", """{"noop":true}""");

        var headerValue = MaskedHeaderValue(response);
        Assert.NotNull(headerValue);
        Assert.DoesNotContain(";body=", headerValue);
    }

    [Fact]
    public async Task Case6_404_UnmatchedRoute_HeaderPresent_NoBodyField()
    {
        var env = BuildServer();
        // The signature covers the raw request path, not a matched endpoint template (ReplayVerifier.BuildRawRoute),
        // so it still verifies even though no endpoint exists for this route; routing's own 404 has an empty
        // body, which is trivially masked exactly like Case5.
        var response = await SendSignedRequestAsync(env, HttpMethod.Post, "/diag/does-not-exist", """{"noop":true}""");

        Assert.Equal(System.Net.HttpStatusCode.NotFound, response.StatusCode);
        var headerValue = MaskedHeaderValue(response);
        Assert.NotNull(headerValue);
        Assert.DoesNotContain(";body=", headerValue);
    }

    /// <summary>An outer exception-handler middleware (registered BEFORE <c>JakapilCaptureMiddleware</c>) writes
    /// its 500 response DIRECTLY to <c>context.Response</c> while unwinding the exception —
    /// <see cref="JakapilCaptureMiddleware.FinalizeReplayResponseAsync"/> only runs later, deferred into
    /// <c>HttpResponse.OnCompleted</c>, so it can observe that write at all (see
    /// <see cref="JakapilCaptureMiddleware.InvokeReplayAsync"/>'s remarks). By the time it runs, under
    /// <c>TestServer</c>, the response is already considered complete: <c>SetMaskedHeader</c>'s own
    /// <c>HttpResponse.HasStarted</c> guard silently no-ops (so no confirmation header — unrelated to and
    /// unchanged by this fix), and the finalization's own body write no longer reaches the materialized
    /// <see cref="HttpResponseMessage"/> either (this mirrors <c>Case8</c>'s TestServer-specific caveat — a
    /// real Kestrel host's timing may differ). The only thing reliably assertable here is the status code the
    /// outer handler set and that the confirmation header stays absent.</summary>
    [Fact]
    public async Task Case7_Exception_OuterHandlerWrites500ProblemJson_HeaderAbsent()
    {
        var env = BuildOuterExceptionServer(withOuterHandler: true);
        var response = await SendSignedRequestAsync(env, HttpMethod.Post, "/diag/exception", """{"noop":true}""");

        Assert.Equal(System.Net.HttpStatusCode.InternalServerError, response.StatusCode);
        Assert.False(response.Headers.Contains(ReplayProtocol.MaskedResponseHeaderName));
    }

    [Fact]
    public async Task Case8_Exception_NoOuterHandler_PropagatesToClient()
    {
        var env = BuildOuterExceptionServer(withOuterHandler: false);

        // With no outer exception-handler middleware, TestServer propagates the exception directly to the
        // SendAsync call (unlike a real Kestrel host, which would produce a bare 500) — there is no HTTP
        // response at all to assert a header against here, so the only meaningful assertion is that this
        // (documented TestServer-specific) behavior still holds.
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => SendSignedRequestAsync(env, HttpMethod.Post, "/diag/exception", """{"noop":true}"""));
    }

    /// <summary>Malformed JSON is NOT the same as a non-JSON content type: the Content-Type claims JSON, but the
    /// body fails to parse. This must stay fail-closed exactly like before the fix — no header at all — since
    /// the body's content could not be classified (distinguishing this from Case3 is the whole point of
    /// <see cref="IAnonymizer.IsReplayResponseBodyJson"/>).</summary>
    [Fact]
    public async Task Case9_409_MalformedJson_HeaderAbsent()
    {
        var env = BuildServer();
        var response = await SendSignedRequestAsync(env, HttpMethod.Post, "/diag/409-malformed-json", """{"noop":true}""");

        Assert.False(response.Headers.Contains(ReplayProtocol.MaskedResponseHeaderName));

        // Fail-closed still forwards the live (unparseable) body unchanged — it is not silently dropped.
        var bodyBytes = await response.Content.ReadAsByteArrayAsync();
        Assert.Equal("{not valid json"u8.ToArray(), bodyBytes);
    }

    /// <summary>A truncated body (exceeding <c>Replay.MaxMaskedResponseBytes</c>) must stay unmasked and
    /// header-absent — unlike the non-JSON pass-through case, its buffered bytes are only a PREFIX of what the
    /// application actually wrote, so even forwarding it "as-is" with an honest disposition flag would be
    /// forwarding something the caller never actually sent in full; it cannot be trusted even for pass-through
    /// purposes. (General truncation-of-capture coverage also exists in
    /// <c>Jakapil.Capture.Tests.Replay.ReplayMiddlewareTests</c>'s <c>BuildServer(maxMaskedResponseBytes:)</c>
    /// parameter; this case exists here too so the full masking-header matrix — every case that determines
    /// whether the header is present/absent — lives in one place.)</summary>
    [Fact]
    public async Task Case10_ResponseExceedsMaxMaskedResponseBytes_HeaderAbsent_BodyTruncatedPrefix()
    {
        const int maxMaskedResponseBytes = 10;
        var env = BuildServer(maxMaskedResponseBytes);
        var response = await SendSignedRequestAsync(env, HttpMethod.Post, "/diag/large-text", """{"noop":true}""");

        Assert.False(response.Headers.Contains(ReplayProtocol.MaskedResponseHeaderName));

        var bodyBytes = await response.Content.ReadAsByteArrayAsync();
        Assert.Equal(maxMaskedResponseBytes, bodyBytes.Length);
        Assert.Equal(new string('x', maxMaskedResponseBytes), Encoding.UTF8.GetString(bodyBytes));
    }
}
