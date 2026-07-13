using System.Net;
using System.Net.Http.Headers;
using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Jakapil.Capture;
using Jakapil.Capture.Contracts;

namespace Jakapil.Capture.Tests;

/// <summary>
/// Runs JakapilCaptureMiddleware on an in-memory TestServer: a minimal endpoint echoes the request
/// body and returns a known JSON response. These tests verify that: (a) request buffering does not
/// prevent downstream handlers from reading the body; (b) the response the client sees is byte-for-byte
/// unchanged by swapping the response stream; (c) the <see cref="CapturedInteraction"/> contract handed
/// to the queue reflects the real route template, untruncated request/response bodies, and masked
/// sensitive headers.
/// </summary>
public class JakapilCaptureMiddlewareTests
{
    /// <summary>A fake queue that accumulates captured interactions in memory, provided for verification.</summary>
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

    /// <summary>Waits for the capture on the exception path (deferred, finalized inside OnCompleted) to arrive, then
    /// verifies there is exactly one interaction. Normal-path captures are synchronous and never need this.</summary>
    private static async Task<CapturedInteraction> WaitForSingleCaptureAsync(RecordingQueue queue, int timeoutMs = 5000)
    {
        var deadline = Environment.TickCount64 + timeoutMs;
        while (queue.Captured.Count == 0 && Environment.TickCount64 < deadline)
        {
            await Task.Delay(10);
        }

        return Assert.Single(queue.Captured);
    }

    /// <summary>Sets up a minimal TestServer with routing + the capture middleware + endpoints that echo the request
    /// body, stream (SSE), and return a large body; returns it together with the recording queue.</summary>
    private static (TestServer Server, RecordingQueue Queue) BuildServer(
        Action<JakapilCaptureOptions>? configure = null, ICaptureRuntimeState? runtimeState = null)
    {
        var queue = new RecordingQueue();

        var host = new HostBuilder()
            .ConfigureWebHost(webBuilder =>
            {
                webBuilder
                    .UseTestServer()
                    .ConfigureServices(services =>
                    {
                        services.Configure<JakapilCaptureOptions>(o => configure?.Invoke(o));
                        services.AddSingleton<ICapturedInteractionQueue>(queue);
                        services.AddSingleton<IAuthTokenRegistry, AuthTokenRegistry>();
                        services.AddSingleton(runtimeState ?? new CaptureRuntimeState());
                        services.AddRouting();
                        services.AddLogging();
                    })
                    .Configure(app =>
                    {
                        app.UseRouting();
                        app.UseMiddleware<JakapilCaptureMiddleware>();
                        app.UseEndpoints(endpoints =>
                        {
                            endpoints.MapPost("/api/products/{id:int}", async context =>
                            {
                                using var reader = new StreamReader(context.Request.Body);
                                var body = await reader.ReadToEndAsync();

                                context.Response.StatusCode = 201;
                                context.Response.ContentType = "application/json";
                                await context.Response.WriteAsync($$"""{"id":{{context.Request.RouteValues["id"]}},"echo":{{body}}}""");
                            }).WithName("EchoProduct");

                            endpoints.MapGet("/stream", async context =>
                            {
                                context.Response.ContentType = "text/event-stream";
                                for (var i = 0; i < 3; i++)
                                {
                                    await context.Response.WriteAsync($"data: event{i}\n\n");
                                    await context.Response.Body.FlushAsync();
                                }
                            }).WithName("Stream");

                            endpoints.MapGet("/big", async context =>
                            {
                                context.Response.ContentType = "application/json";
                                await context.Response.WriteAsync("\"" + new string('x', 500) + "\"");
                            }).WithName("Big");
                        });
                    });
            })
            .Start();

        return (host.GetTestServer(), queue);
    }

    /// <summary>Phase 14 M4: when local <c>Enabled=true</c> but the remote runtime state drops to <c>false</c>
    /// (a shutdown delivered by the SDK's remote config poll), capture STOPS — nothing is captured, nothing is
    /// written to the queue — yet the host request still executes fully and the client receives the normal response.</summary>
    [Fact]
    public async Task Middleware_RemoteDisabled_NoCapture_ButHostRequestUnaffected()
    {
        var runtimeState = new CaptureRuntimeState();
        runtimeState.SetEnabled(false);
        var (server, queue) = BuildServer(runtimeState: runtimeState);
        using var client = server.CreateClient();

        var response = await client.PostAsync("/api/products/4",
            new StringContent("""{"name":"Widget","price":9.99}""", Encoding.UTF8, "application/json"));
        var responseText = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        Assert.Equal("""{"id":4,"echo":{"name":"Widget","price":9.99}}""", responseText);
        Assert.Empty(queue.Captured);
    }

    /// <summary>Phase 14 M4 security invariant: local <c>Enabled=false</c> is a HARD floor — capture can NEVER be
    /// turned on even if the remote runtime state is <c>true</c>.</summary>
    [Fact]
    public async Task Middleware_LocalDisabled_CannotBeOverriddenByRemoteEnabled()
    {
        var runtimeState = new CaptureRuntimeState();
        runtimeState.SetEnabled(true);
        var (server, queue) = BuildServer(o => o.Enabled = false, runtimeState);
        using var client = server.CreateClient();

        await client.PostAsync("/api/products/4",
            new StringContent("""{"name":"Widget","price":9.99}""", Encoding.UTF8, "application/json"));

        Assert.Empty(queue.Captured);
    }

    /// <summary>When both the local AND remote state are enabled (same as pre-M4 behavior), capture works normally.</summary>
    [Fact]
    public async Task Middleware_LocalAndRemoteEnabled_CapturesNormally()
    {
        var runtimeState = new CaptureRuntimeState();
        runtimeState.SetEnabled(true);
        var (server, queue) = BuildServer(runtimeState: runtimeState);
        using var client = server.CreateClient();

        await client.PostAsync("/api/products/4",
            new StringContent("""{"name":"Widget","price":9.99}""", Encoding.UTF8, "application/json"));

        Assert.Single(queue.Captured);
    }

    /// <summary>Verifies the client sees exactly the response bytes the endpoint wrote; capture does not alter the response.</summary>
    [Fact]
    public async Task Middleware_DoesNotAlterResponse_ClientSeesExactBytesTheEndpointWrote()
    {
        var (server, _) = BuildServer();
        using var client = server.CreateClient();

        var requestJson = """{"name":"Widget","price":9.99}""";
        var response = await client.PostAsync("/api/products/4",
            new StringContent(requestJson, Encoding.UTF8, "application/json"));

        var responseText = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        Assert.Equal("""{"id":4,"echo":{"name":"Widget","price":9.99}}""", responseText);
    }

    /// <summary>Verifies that because the middleware rewinds the position after buffering the request body for capture
    /// (EnableBuffering + rewind), the downstream endpoint can still read and echo the body.</summary>
    [Fact]
    public async Task Middleware_RewindsRequestBody_DownstreamHandlerStillReadsIt()
    {
        var (server, _) = BuildServer();
        using var client = server.CreateClient();

        var requestJson = """{"name":"Gadget","price":19.99}""";
        var response = await client.PostAsync("/api/products/7",
            new StringContent(requestJson, Encoding.UTF8, "application/json"));

        var responseText = await response.Content.ReadAsStringAsync();

        Assert.Contains("\"echo\":{\"name\":\"Gadget\",\"price\":19.99}", responseText);
    }

    /// <summary>Verifies the captured interaction carries the complete route template, method, status code, route
    /// parameters, and untruncated request/response bodies.</summary>
    [Fact]
    public async Task Middleware_CapturesFullRequestAndResponseBodies_Untruncated_WithRouteTemplate()
    {
        var (server, queue) = BuildServer();
        using var client = server.CreateClient();

        var requestJson = """{"name":"Widget","price":9.99}""";
        await client.PostAsync("/api/products/4",
            new StringContent(requestJson, Encoding.UTF8, "application/json"));

        var interaction = Assert.Single(queue.Captured);

        Assert.Equal("/api/products/{id:int}", interaction.Endpoint.RouteTemplate);
        Assert.Equal("POST", interaction.Request.Method);
        Assert.Equal(201, interaction.Response.StatusCode);

        var idParam = Assert.Single(interaction.Request.RouteParameters, p => p.Name == "id");
        Assert.Equal("4", idParam.Value);
        Assert.Equal("int", idParam.ClrType);

        Assert.NotNull(interaction.Request.Body);
        Assert.False(interaction.Request.Body!.Truncated);
        Assert.Equal(requestJson, interaction.Request.Body.Text);

        Assert.NotNull(interaction.Response.Body);
        Assert.False(interaction.Response.Body!.Truncated);
        Assert.Equal("""{"id":4,"echo":{"name":"Widget","price":9.99}}""", interaction.Response.Body.Text);
    }

    /// <summary>R0.3: the <c>action</c>/<c>controller</c> infrastructure values added by MVC route routing
    /// are not real parameters and must be filtered out; only the real route parameter (<c>id</c>) should be carried.
    /// The previous buggy guard only did <c>continue</c> on a <c>null</c> value and never filtered out action/controller.</summary>
    [Fact]
    public void CaptureBuilder_Build_ActionAndControllerRouteValues_AreExcludedFromRouteParameters()
    {
        var context = new DefaultHttpContext();
        context.Request.Method = "GET";
        context.Request.Path = "/orders/5";
        context.Request.RouteValues = new RouteValueDictionary
        {
            ["controller"] = "Orders",
            ["action"] = "Get",
            ["id"] = "5",
        };

        var interaction = CaptureBuilder.Build(
            context,
            requestStart: DateTimeOffset.UtcNow,
            durationMs: 1,
            requestBody: null,
            responseBody: null,
            exception: null,
            options: new JakapilCaptureOptions());

        var idParam = Assert.Single(interaction.Request.RouteParameters);
        Assert.Equal("id", idParam.Name);
        Assert.Equal("5", idParam.Value);
        Assert.DoesNotContain(interaction.Request.RouteParameters, p => p.Name == "action");
        Assert.DoesNotContain(interaction.Request.RouteParameters, p => p.Name == "controller");
    }

    /// <summary>Masking at capture time: the Authorization value is replaced with the Bearer scheme + bullet marks
    /// + the last 4 characters before it reaches the contract DTO handed to the queue; the raw token never leaks.</summary>
    [Fact]
    public async Task Middleware_MasksSensitiveRequestHeader_InCapturedContract()
    {
        var (server, queue) = BuildServer();
        using var client = server.CreateClient();

        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/products/4")
        {
            Content = new StringContent("""{"name":"Widget","price":9.99}""", Encoding.UTF8, "application/json"),
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "supersecrettoken9999");

        await client.SendAsync(request);

        var interaction = Assert.Single(queue.Captured);
        var auth = Assert.Contains("Authorization", interaction.Request.Headers);
        Assert.StartsWith("Bearer ", auth);
        Assert.Contains("••••••••", auth);
        Assert.EndsWith("9999", auth);
        Assert.DoesNotContain("supersecrettoken", auth);
    }

    /// <summary>Verifies that for a streaming content type (SSE) the client receives exactly the payload the endpoint
    /// wrote, and the interaction is still captured but metadata-only (the streamed body is not buffered).</summary>
    [Fact]
    public async Task Middleware_StreamingContentType_IsCapturedMetadataOnly_ResponseUnaltered()
    {
        var (server, queue) = BuildServer();
        using var client = server.CreateClient();

        var response = await client.GetAsync("/stream");
        var text = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("data: event0\n\ndata: event1\n\ndata: event2\n\n", text);

        var interaction = Assert.Single(queue.Captured);
        Assert.Equal(200, interaction.Response.StatusCode);
        Assert.Null(interaction.Response.Body?.Text);
    }

    /// <summary>Verifies that with a small capture cap the captured copy is bounded and marked truncated, yet the
    /// client still receives every byte; the real body size is still recorded.</summary>
    [Fact]
    public async Task Middleware_ResponseOverCaptureCap_TruncatesCaptureButNotTheWire()
    {
        var (server, queue) = BuildServer(o => o.MaxCapturedResponseBytes = 64);
        using var client = server.CreateClient();

        var response = await client.GetAsync("/big");
        var text = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("\"" + new string('x', 500) + "\"", text);

        var interaction = Assert.Single(queue.Captured);
        Assert.NotNull(interaction.Response.Body);
        Assert.True(interaction.Response.Body!.Truncated);
        Assert.Equal(502, interaction.Response.Body.ByteSize);
    }

    /// <summary>
    /// Sets up a server mimicking an e-commerce app that places the capture middleware BEFORE
    /// <c>UseStatusCodePagesWithReExecute("/errors/{0}")</c>: anonymous access to an [Authorize]-style endpoint
    /// (here a bodyless 401) is re-executed at <c>/errors/401</c>. By the time capture finalizes,
    /// <c>context.GetEndpoint()</c> is now the error endpoint — the middleware must capture the ORIGINAL instead.
    /// </summary>
    private static (TestServer Server, RecordingQueue Queue) BuildReExecuteServer()
    {
        var queue = new RecordingQueue();
        var host = new HostBuilder()
            .ConfigureWebHost(webBuilder =>
            {
                webBuilder
                    .UseTestServer()
                    .ConfigureServices(services =>
                    {
                        services.Configure<JakapilCaptureOptions>(_ => { });
                        services.AddSingleton<ICapturedInteractionQueue>(queue);
                        services.AddSingleton<IAuthTokenRegistry, AuthTokenRegistry>();
                        services.AddSingleton<ICaptureRuntimeState>(new CaptureRuntimeState());
                        services.AddRouting();
                        services.AddLogging();
                    })
                    .Configure(app =>
                    {
                        app.UseMiddleware<JakapilCaptureMiddleware>();
                        app.UseStatusCodePagesWithReExecute("/errors/{0}");
                        app.UseRouting();
                        app.UseEndpoints(endpoints =>
                        {
                            endpoints.MapGet("/api/orders/{id:int}", context =>
                            {
                                context.Response.StatusCode = 401;
                                return Task.CompletedTask;
                            });

                            endpoints.MapGet("/errors/{code:int}", async context =>
                            {
                                context.Response.ContentType = "application/json";
                                await context.Response.WriteAsync($$"""{"error":{{context.Request.RouteValues["code"]}}}""");
                            });
                        });
                    });
            })
            .Start();

        return (host.GetTestServer(), queue);
    }

    /// <summary>Verifies that for a response re-executed by status-code-pages, the captured path and route template
    /// are the ORIGINAL endpoint (never the re-executed <c>/errors/{code}</c>), the fake error route value
    /// (<c>{code}=401</c>) does not leak as a request route parameter, and the status is honestly captured as 401.</summary>
    [Fact]
    public async Task Middleware_ReExecutedByStatusCodePages_CapturesOriginalEndpoint_NotTheErrorRoute()
    {
        var (server, queue) = BuildReExecuteServer();
        using var client = server.CreateClient();

        var response = await client.GetAsync("/api/orders/42");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);

        var interaction = Assert.Single(queue.Captured);

        Assert.Equal("/api/orders/42", interaction.Request.RawPath);
        Assert.Equal("/api/orders/42", interaction.Endpoint.RouteTemplate);
        Assert.DoesNotContain("errors", interaction.Endpoint.RouteTemplate, StringComparison.OrdinalIgnoreCase);

        Assert.DoesNotContain(interaction.Request.RouteParameters, p => p.Name == "code");

        Assert.Equal(401, interaction.Response.StatusCode);
    }

    /// <summary>Guard: verifies the OnStarting snapshot is a no-op on ordinary responses that are not re-executed,
    /// and the real route template and route parameters are still captured.</summary>
    [Fact]
    public async Task Middleware_NormalResponse_NotReExecuted_StillCapturesRealRouteTemplate()
    {
        var (server, queue) = BuildServer();
        using var client = server.CreateClient();

        await client.PostAsync("/api/products/9", new StringContent("""{"name":"X","price":1}""", Encoding.UTF8, "application/json"));

        var interaction = Assert.Single(queue.Captured);
        Assert.Equal("/api/products/{id:int}", interaction.Endpoint.RouteTemplate);
        Assert.Contains(interaction.Request.RouteParameters, p => p.Name == "id" && p.Value == "9");
    }

    /// <summary>
    /// Sets up a server mimicking the pipeline of a target app that registers its own exception-handling middleware
    /// BEFORE <c>UseJakapilCapture()</c> — that is, OUTSIDE the capture middleware. When an endpoint throws an
    /// exception our middleware unwinds first (at that point the default 200, empty body); but then the outer
    /// middleware translates the exception into the real status code + JSON error body. Capture must reflect that
    /// FINAL response, not the transient 200.
    /// </summary>
    private static (TestServer Server, RecordingQueue Queue) BuildOuterExceptionServer(bool swallow)
    {
        var queue = new RecordingQueue();
        var host = new HostBuilder()
            .ConfigureWebHost(webBuilder =>
            {
                webBuilder
                    .UseTestServer()
                    .ConfigureServices(services =>
                    {
                        services.Configure<JakapilCaptureOptions>(_ => { });
                        services.AddSingleton<ICapturedInteractionQueue>(queue);
                        services.AddSingleton<IAuthTokenRegistry, AuthTokenRegistry>();
                        services.AddSingleton<ICaptureRuntimeState>(new CaptureRuntimeState());
                        services.AddRouting();
                        services.AddLogging();
                    })
                    .Configure(app =>
                    {
                        app.UseDeveloperExceptionPage();

                        if (swallow)
                        {
                            app.Use(async (context, next) =>
                            {
                                try
                                {
                                    await next(context);
                                }
                                catch (InvalidOperationException ex)
                                {
                                    context.Response.StatusCode = 409;
                                    context.Response.ContentType = "application/json";
                                    await context.Response.WriteAsync($$"""{"error":"duplicate","detail":"{{ex.Message}}"}""");
                                }
                            });
                        }

                        app.UseMiddleware<JakapilCaptureMiddleware>();
                        app.UseRouting();
                        app.UseEndpoints(endpoints =>
                        {
                            endpoints.MapGet("/api/basket/checkout", context =>
                                throw new InvalidOperationException("basket already checked out"));

                            endpoints.MapGet("/api/products/{id:int}", async context =>
                            {
                                context.Response.StatusCode = 200;
                                context.Response.ContentType = "application/json";
                                await context.Response.WriteAsync($$"""{"id":{{context.Request.RouteValues["id"]}}}""");
                            });
                        });
                    });
            })
            .Start();

        return (host.GetTestServer(), queue);
    }

    /// <summary>Verifies that when the outer middleware swallows the exception and produces 409 + a JSON body, capture
    /// records that FINAL status and the real error body rather than the transient 200 + empty body, and that the
    /// exception-mediated flag is preserved. Since the capture on the exception path finalizes inside
    /// Response.OnCompleted, a deferred callback is awaited.</summary>
    [Fact]
    public async Task Middleware_OuterExceptionMiddlewareTranslatesException_CapturesFinalStatusAndErrorBody()
    {
        var (server, queue) = BuildOuterExceptionServer(swallow: true);
        using var client = server.CreateClient();

        var response = await client.GetAsync("/api/basket/checkout");
        var body = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        Assert.Contains("duplicate", body);

        var interaction = await WaitForSingleCaptureAsync(queue);
        Assert.Equal(409, interaction.Response.StatusCode);
        Assert.NotNull(interaction.Response.Body);
        Assert.Contains("duplicate", interaction.Response.Body!.Text);
        Assert.NotNull(interaction.Exception);
        Assert.Contains("basket already checked out", interaction.Exception!.Message);
    }

    /// <summary>Verifies that when no outer middleware swallows the exception, the host produces a 500 and capture
    /// records an honest 500 server-error status rather than 200.</summary>
    [Fact]
    public async Task Middleware_ExceptionNotSwallowed_CapturesHostErrorStatus()
    {
        var (server, queue) = BuildOuterExceptionServer(swallow: false);
        using var client = server.CreateClient();

        var response = await client.GetAsync("/api/basket/checkout");

        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);

        var interaction = await WaitForSingleCaptureAsync(queue);
        Assert.Equal(500, interaction.Response.StatusCode);
        Assert.NotNull(interaction.Exception);
    }

    /// <summary>Verifies the non-exception path through the same pipeline is captured exactly as before: a single
    /// capture (no double-dispatch from OnCompleted), the correct 200 status and body, and no exception flag.</summary>
    [Fact]
    public async Task Middleware_NormalResponseThroughOuterExceptionServer_CapturedRegressionFree()
    {
        var (server, queue) = BuildOuterExceptionServer(swallow: true);
        using var client = server.CreateClient();

        var response = await client.GetAsync("/api/products/7");
        var body = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("""{"id":7}""", body);

        var interaction = Assert.Single(queue.Captured);
        Assert.Equal(200, interaction.Response.StatusCode);
        Assert.Equal("""{"id":7}""", interaction.Response.Body!.Text);
        Assert.Null(interaction.Exception);
    }
}
