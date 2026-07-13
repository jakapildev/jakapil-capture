using System.Net;
using System.Text;
using System.Text.Json;
using Jakapil.Capture;
using Jakapil.Capture.Contracts;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Jakapil.Capture.Tests;

/// <summary>
/// Verifies <see cref="CaptureConfigPollWorker.PollOnceAsync"/> (the full logic of a single poll round) in isolation:
/// a successful response updates <see cref="CaptureRuntimeState"/> and returns the interval the server returned;
/// unreachability/a failure status code PRESERVES the last known state; the queue is dropped only on the
/// enabled→disabled transition (not on disabled→enabled). The <see cref="BackgroundService.ExecuteAsync"/> loop
/// (timing-dependent) is deliberately not tested here — <c>PollOnceAsync</c> is its testable core unit.
/// </summary>
public sealed class CaptureConfigPollWorkerTests
{
    private static readonly JsonSerializerOptions WireJson = new(JsonSerializerDefaults.Web);

    /// <summary>A fake <see cref="HttpMessageHandler"/> for tests that applies the given delegate to each request.</summary>
    private sealed class FakeHttpMessageHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, HttpResponseMessage> _respond;
        public HttpRequestMessage? LastRequest { get; private set; }

        public FakeHttpMessageHandler(Func<HttpRequestMessage, HttpResponseMessage> respond) => _respond = respond;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            LastRequest = request;
            return Task.FromResult(_respond(request));
        }
    }

    /// <summary>A minimal <see cref="IHttpClientFactory"/> fake that returns a single fixed <see cref="HttpClient"/>.</summary>
    private sealed class FakeHttpClientFactory : IHttpClientFactory
    {
        private readonly HttpClient _client;
        public FakeHttpClientFactory(HttpClient client) => _client = client;
        public HttpClient CreateClient(string name) => _client;
    }

    /// <summary>A fake queue that only counts the number of <see cref="Clear"/> calls and never writes to the queue.</summary>
    private sealed class CountingQueue : ICapturedInteractionQueue
    {
        public int ClearCallCount { get; private set; }
        public ValueTask EnqueueAsync(Jakapil.Capture.Contracts.CapturedInteraction interaction, CancellationToken ct = default) => ValueTask.CompletedTask;
        public void Clear() => ClearCallCount++;
    }

    private static CaptureConfigPollWorker BuildWorker(
        Func<HttpRequestMessage, HttpResponseMessage> respond, CaptureRuntimeState state, CountingQueue queue)
    {
        var handler = new FakeHttpMessageHandler(respond);
        var client = new HttpClient(handler);
        var factory = new FakeHttpClientFactory(client);
        var options = Options.Create(new JakapilCaptureOptions
        {
            Enabled = true,
            CollectorUri = "http://collector.test",
            IngestKey = "ik_test",
        });

        return new CaptureConfigPollWorker(factory, options, state, queue, TimeProvider.System, NullLogger<CaptureConfigPollWorker>.Instance);
    }

    private static HttpResponseMessage JsonResponse(HttpStatusCode statusCode, CaptureConfigResponse body) => new(statusCode)
    {
        Content = new StringContent(JsonSerializer.Serialize(body, WireJson), Encoding.UTF8, "application/json"),
    };

    /// <summary>A successful response updates the runtime state to what the server said and returns the server's
    /// returned <c>pollIntervalSeconds</c> as the next interval.</summary>
    [Fact]
    public async Task PollOnceAsync_SuccessfulResponse_UpdatesStateAndReturnsServerInterval()
    {
        var state = new CaptureRuntimeState();
        var queue = new CountingQueue();
        var worker = BuildWorker(_ => JsonResponse(HttpStatusCode.OK, new CaptureConfigResponse { Enabled = false, Revision = 3, PollIntervalSeconds = 5 }), state, queue);

        var nextInterval = await worker.PollOnceAsync(new JakapilCaptureOptions { CollectorUri = "http://collector.test", IngestKey = "ik_test" }, TimeSpan.FromSeconds(15), CancellationToken.None);

        Assert.False(state.Enabled);
        Assert.Equal(TimeSpan.FromSeconds(5), nextInterval);
    }

    /// <summary>The server is called with the <c>X-Jakapil-Key</c> header (same auth as the ingest path).</summary>
    [Fact]
    public async Task PollOnceAsync_Request_CarriesIngestKeyHeader()
    {
        var state = new CaptureRuntimeState();
        var queue = new CountingQueue();
        HttpRequestMessage? seen = null;
        var worker = BuildWorker(req =>
        {
            seen = req;
            return JsonResponse(HttpStatusCode.OK, new CaptureConfigResponse { Enabled = true, Revision = 0, PollIntervalSeconds = 15 });
        }, state, queue);

        await worker.PollOnceAsync(new JakapilCaptureOptions { CollectorUri = "http://collector.test", IngestKey = "ik_test_123" }, TimeSpan.FromSeconds(15), CancellationToken.None);

        Assert.NotNull(seen);
        Assert.Equal("ik_test_123", seen!.Headers.GetValues("X-Jakapil-Key").Single());
        Assert.EndsWith("/ingest/config", seen.RequestUri!.AbsolutePath);
    }

    /// <summary>If a failure status code (e.g. 500) comes from the server, the last known state is PRESERVED and the
    /// current interval is returned unchanged.</summary>
    [Fact]
    public async Task PollOnceAsync_FailureStatusCode_PreservesLastKnownState()
    {
        var state = new CaptureRuntimeState();
        state.SetEnabled(true);
        var queue = new CountingQueue();
        var worker = BuildWorker(_ => new HttpResponseMessage(HttpStatusCode.InternalServerError), state, queue);

        var nextInterval = await worker.PollOnceAsync(new JakapilCaptureOptions { CollectorUri = "http://collector.test", IngestKey = "ik_test" }, TimeSpan.FromSeconds(15), CancellationToken.None);

        Assert.True(state.Enabled);
        Assert.Equal(TimeSpan.FromSeconds(15), nextInterval);
        Assert.Equal(0, queue.ClearCallCount);
    }

    /// <summary>On a network error (exception) too, the last known state is PRESERVED; the exception is swallowed (the host request is never affected).</summary>
    [Fact]
    public async Task PollOnceAsync_NetworkError_PreservesLastKnownState_AndDoesNotThrow()
    {
        var state = new CaptureRuntimeState();
        state.SetEnabled(true);
        var queue = new CountingQueue();
        var worker = BuildWorker(_ => throw new HttpRequestException("collector unreachable"), state, queue);

        var nextInterval = await worker.PollOnceAsync(new JakapilCaptureOptions { CollectorUri = "http://collector.test", IngestKey = "ik_test" }, TimeSpan.FromSeconds(15), CancellationToken.None);

        Assert.True(state.Enabled);
        Assert.Equal(TimeSpan.FromSeconds(15), nextInterval);
    }

    /// <summary>Phase 14 M4: on the enabled→disabled transition the queue is dropped (<c>Clear</c> is called exactly once).</summary>
    [Fact]
    public async Task PollOnceAsync_EnabledToDisabled_DropsQueue()
    {
        var state = new CaptureRuntimeState();
        state.SetEnabled(true);
        var queue = new CountingQueue();
        var worker = BuildWorker(_ => JsonResponse(HttpStatusCode.OK, new CaptureConfigResponse { Enabled = false, Revision = 1, PollIntervalSeconds = 15 }), state, queue);

        await worker.PollOnceAsync(new JakapilCaptureOptions { CollectorUri = "http://collector.test", IngestKey = "ik_test" }, TimeSpan.FromSeconds(15), CancellationToken.None);

        Assert.Equal(1, queue.ClearCallCount);
    }

    /// <summary>On the disabled→enabled transition (the reverse of a shutdown) the queue is NOT dropped — dropping happens only in the shutdown direction.</summary>
    [Fact]
    public async Task PollOnceAsync_DisabledToEnabled_DoesNotDropQueue()
    {
        var state = new CaptureRuntimeState();
        state.SetEnabled(false);
        var queue = new CountingQueue();
        var worker = BuildWorker(_ => JsonResponse(HttpStatusCode.OK, new CaptureConfigResponse { Enabled = true, Revision = 1, PollIntervalSeconds = 15 }), state, queue);

        await worker.PollOnceAsync(new JakapilCaptureOptions { CollectorUri = "http://collector.test", IngestKey = "ik_test" }, TimeSpan.FromSeconds(15), CancellationToken.None);

        Assert.Equal(0, queue.ClearCallCount);
        Assert.True(state.Enabled);
    }

    /// <summary>On an enabled→enabled (unchanged) transition the queue is not dropped.</summary>
    [Fact]
    public async Task PollOnceAsync_EnabledToEnabled_DoesNotDropQueue()
    {
        var state = new CaptureRuntimeState();
        state.SetEnabled(true);
        var queue = new CountingQueue();
        var worker = BuildWorker(_ => JsonResponse(HttpStatusCode.OK, new CaptureConfigResponse { Enabled = true, Revision = 2, PollIntervalSeconds = 15 }), state, queue);

        await worker.PollOnceAsync(new JakapilCaptureOptions { CollectorUri = "http://collector.test", IngestKey = "ik_test" }, TimeSpan.FromSeconds(15), CancellationToken.None);

        Assert.Equal(0, queue.ClearCallCount);
    }
}
