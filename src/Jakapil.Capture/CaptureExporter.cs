using System.IO.Compression;
using System.Net.Http.Headers;
using System.Text.Json;
using Jakapil.Capture.Contracts;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Jakapil.Capture;

/// <summary>
/// The component that transports captured interaction batches to the collector's <c>POST /ingest</c> endpoint.
/// </summary>
/// <remarks>
/// JSON serialization, gzip compression, HTTP request setup/sending, and logging of the result
/// (success/collector-rejection/error) are this class's responsibility. <see cref="ExportWorker"/> only manages
/// the lifecycle (waiting/draining/flush-triggering) and hands the batch it drained to this class — so the
/// transport logic can be tested independently. HttpClient ownership lies with <see cref="IHttpClientFactory"/>
/// (named client <see cref="HttpClientName"/>); this class obtains the client from the factory on every call and
/// does not dispose it — exactly matching the existing behavior.
/// </remarks>
internal sealed class CaptureExporter
{
    /// <summary>The named <see cref="IHttpClientFactory"/> client used for export requests.</summary>
    internal const string HttpClientName = "jakapil-capture-export";

    /// <summary>The SDK version sent in the <c>X-Jakapil-SDK</c> header.</summary>
    internal const string SdkVersion = "1.1.0";

    private static readonly JsonSerializerOptions WireJson = new(JsonSerializerDefaults.Web);

    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IOptions<JakapilCaptureOptions> _options;
    private readonly ILogger<CaptureExporter> _logger;

    /// <summary>Constructs the transporter with the HttpClient factory, options, and logger.</summary>
    public CaptureExporter(IHttpClientFactory httpClientFactory, IOptions<JakapilCaptureOptions> options, ILogger<CaptureExporter> logger)
    {
        _httpClientFactory = httpClientFactory;
        _options = options;
        _logger = logger;
    }

    /// <summary>
    /// Sends the given batch to the collector as gzipped JSON via <c>POST /ingest</c>. If the batch is empty,
    /// returns 0 without sending a request. If sending fails (unsuccessful status code or exception), the batch
    /// is dropped (the caller does not re-enqueue) and 0 is returned; on success, returns the number of items sent.
    /// </summary>
    internal async Task<int> SendBatchAsync(IReadOnlyList<CapturedInteraction> batch, CancellationToken cancellationToken)
    {
        if (batch.Count == 0)
        {
            return 0;
        }

        var opts = _options.Value;
        var payload = JsonSerializer.SerializeToUtf8Bytes(batch, WireJson);

        byte[] gzipped;
        using (var compressed = new MemoryStream())
        {
            using (var gzip = new GZipStream(compressed, CompressionMode.Compress, leaveOpen: true))
            {
                await gzip.WriteAsync(payload, cancellationToken);
            }

            gzipped = compressed.ToArray();
        }

        var client = _httpClientFactory.CreateClient(HttpClientName);
        var url = opts.CollectorUri!.TrimEnd('/') + "/ingest";

        var content = new ByteArrayContent(gzipped);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        content.Headers.ContentEncoding.Add("gzip");

        var request = new HttpRequestMessage(HttpMethod.Post, url) { Content = content };
        request.Headers.Add("X-Jakapil-Key", opts.IngestKey);
        request.Headers.Add("X-Jakapil-SDK", SdkVersion);
        request.Headers.Add("X-Jakapil-Batch-Id", Guid.NewGuid().ToString());

        try
        {
            var response = await client.SendAsync(request, cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("Jakapil: collector rejected the batch, status code {StatusCode}; {Count} interactions dropped", response.StatusCode, batch.Count);
                return 0;
            }

            return batch.Count;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Jakapil: sending the batch to the collector failed; {Count} interactions dropped", batch.Count);
            return 0;
        }
    }
}
