using System.IO.Compression;
using System.Net;
using System.Text.Json;
using Jakapil.Capture;
using Jakapil.Capture.Contracts;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Jakapil.Capture.Tests;

/// <summary>
/// Verifies the capture queue's (<see cref="CapturedInteractionQueue"/>) drop-oldest (DropOldest) behavior under
/// backpressure, and that the export worker (<see cref="ExportWorker"/>), via its transport
/// (<see cref="CaptureExporter"/>), turns the batch into a gzipped, correctly-headed
/// <c>POST /ingest</c> request; and that when no collector is configured it silently returns 0 without sending
/// any request.
/// </summary>
public class ExportBackpressureTests
{
    /// <summary>A minimal fake <see cref="HttpMessageHandler"/> that captures each request with a fixed response and
    /// stores the body as raw bytes DURING the send (before dispose).</summary>
    private sealed class CapturingHandler : HttpMessageHandler
    {
        private readonly HttpStatusCode _status;

        public CapturingHandler(HttpStatusCode status) => _status = status;

        public List<HttpRequestMessage> Requests { get; } = [];

        public List<byte[]> RequestBodies { get; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var bytes = request.Content is null ? [] : await request.Content.ReadAsByteArrayAsync(cancellationToken);
            Requests.Add(request);
            RequestBodies.Add(bytes);
            return new HttpResponseMessage(_status);
        }
    }

    /// <summary>A minimal <see cref="IHttpClientFactory"/> implementation that, regardless of the name, always returns
    /// an <see cref="HttpClient"/> bound to the same fake handler.</summary>
    private sealed class FakeHttpClientFactory : IHttpClientFactory
    {
        private readonly HttpMessageHandler _handler;

        public FakeHttpClientFactory(HttpMessageHandler handler) => _handler = handler;

        public HttpClient CreateClient(string name) => new(_handler, disposeHandler: false);
    }

    /// <summary>Builds a minimal valid captured interaction that fills in all the mandatory sub-fields the contract requires.</summary>
    private static CapturedInteraction BuildInteraction(string method = "GET", string path = "/api/ping", int statusCode = 200)
    {
        var now = DateTimeOffset.UtcNow;
        return new CapturedInteraction
        {
            Id = Guid.NewGuid(),
            Timestamp = now,
            DurationMs = 3,
            Correlation = new CorrelationSignals { ObservedAt = now },
            Request = new CapturedRequest
            {
                Method = method,
                RawPath = path,
                Headers = new Dictionary<string, string>(),
                RouteParameters = [],
            },
            Response = new CapturedResponse
            {
                StatusCode = statusCode,
                Headers = new Dictionary<string, string>(),
            },
            Endpoint = new EndpointInfo { RouteTemplate = path },
        };
    }

    /// <summary>Verifies that items enqueued beyond the queue capacity with no consumer are dropped via drop-oldest
    /// (DropOldest) and that the dropped count is counted correctly.</summary>
    [Fact]
    public async Task Queue_OverCapacity_DropsOldest_AndCounts()
    {
        var options = Options.Create(new JakapilCaptureOptions { QueueCapacity = 4 });
        var queue = new CapturedInteractionQueue(options);

        for (var i = 0; i < 10; i++)
        {
            await queue.EnqueueAsync(BuildInteraction());
        }

        Assert.Equal(6, queue.DroppedCount);
    }

    /// <summary>Verifies the queued items are sent to <c>POST .../ingest</c> in a gzipped body with the correct
    /// collector-key/sdk/batch-id headers, and that when the gzip is decompressed the interactions (including their
    /// Ids) deserialize completely.</summary>
    [Fact]
    public async Task Flush_SendsGzippedRequestWithCorrectHeaders()
    {
        var interactions = new[] { BuildInteraction(), BuildInteraction(), BuildInteraction() };
        var options = Options.Create(new JakapilCaptureOptions
        {
            CollectorUri = "http://collector.test",
            IngestKey = "ik_test",
            ExportBatchMaxItems = 1000,
            ExportFlushIntervalSeconds = 0,
        });
        var queue = new CapturedInteractionQueue(options);
        foreach (var interaction in interactions)
        {
            await queue.EnqueueAsync(interaction);
        }

        var handler = new CapturingHandler(HttpStatusCode.OK);
        var factory = new FakeHttpClientFactory(handler);
        var exporter = new CaptureExporter(factory, options, NullLogger<CaptureExporter>.Instance);
        var worker = new ExportWorker(queue, exporter, options, TimeProvider.System, NullLogger<ExportWorker>.Instance);

        var sent = await worker.FlushBatchAsync(CancellationToken.None);

        Assert.Equal(3, sent);
        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Post, request.Method);
        Assert.EndsWith("/ingest", request.RequestUri!.AbsolutePath);
        Assert.Equal("ik_test", request.Headers.GetValues("X-Jakapil-Key").Single());
        Assert.Equal(CaptureExporter.SdkVersion, request.Headers.GetValues("X-Jakapil-SDK").Single());
        var batchId = request.Headers.GetValues("X-Jakapil-Batch-Id").Single();
        Assert.True(Guid.TryParse(batchId, out _));
        Assert.Contains("gzip", request.Content!.Headers.ContentEncoding);

        var gzipped = Assert.Single(handler.RequestBodies);
        using var compressed = new MemoryStream(gzipped);
        using var gzip = new GZipStream(compressed, CompressionMode.Decompress);
        using var decompressed = new MemoryStream();
        await gzip.CopyToAsync(decompressed);
        var json = decompressed.ToArray();

        var deserialized = JsonSerializer.Deserialize<List<CapturedInteraction>>(json, new JsonSerializerOptions(JsonSerializerDefaults.Web));

        Assert.NotNull(deserialized);
        Assert.Equal(3, deserialized!.Count);
        Assert.Equal(interactions.Select(i => i.Id).OrderBy(id => id), deserialized.Select(i => i.Id).OrderBy(id => id));
    }

    /// <summary>Verifies that when the collector address is not configured, the export returns 0 without sending any
    /// request and the queued items remain (not drained, not dropped).</summary>
    [Fact]
    public async Task Collector_NotConfigured_DoesNotSend()
    {
        var options = Options.Create(new JakapilCaptureOptions
        {
            CollectorUri = null,
            IngestKey = "ik_test",
            ExportBatchMaxItems = 1000,
            ExportFlushIntervalSeconds = 0,
        });
        var queue = new CapturedInteractionQueue(options);
        await queue.EnqueueAsync(BuildInteraction());
        await queue.EnqueueAsync(BuildInteraction());

        var handler = new CapturingHandler(HttpStatusCode.OK);
        var factory = new FakeHttpClientFactory(handler);
        var exporter = new CaptureExporter(factory, options, NullLogger<CaptureExporter>.Instance);
        var worker = new ExportWorker(queue, exporter, options, TimeProvider.System, NullLogger<ExportWorker>.Instance);

        var sent = await worker.FlushBatchAsync(CancellationToken.None);

        Assert.Equal(0, sent);
        Assert.Empty(handler.Requests);
        Assert.Equal(0, queue.DroppedCount);
    }

    /// <summary>Verifies that when the collector rejects the batch with a failure status code, the transport
    /// (<see cref="CaptureExporter"/>) returns 0 and the batch is not re-queued (by design).</summary>
    [Fact]
    public async Task Collector_RejectsBatch_TransportReturnsZero_AndBatchIsDropped()
    {
        var options = Options.Create(new JakapilCaptureOptions
        {
            CollectorUri = "http://collector.test",
            IngestKey = "ik_test",
        });
        var handler = new CapturingHandler(HttpStatusCode.InternalServerError);
        var factory = new FakeHttpClientFactory(handler);
        var exporter = new CaptureExporter(factory, options, NullLogger<CaptureExporter>.Instance);

        var sent = await exporter.SendBatchAsync([BuildInteraction()], CancellationToken.None);

        Assert.Equal(0, sent);
        Assert.Single(handler.Requests);
    }
}
