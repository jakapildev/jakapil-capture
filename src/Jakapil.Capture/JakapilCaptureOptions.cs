using Microsoft.Extensions.Options;

namespace Jakapil.Capture;

/// <summary>Configuration for the Jakapil capture middleware and the background export worker.</summary>
/// <remarks>
/// How much to capture, how aggressively to sample, which headers to mask, and how/how often captured
/// interactions are shipped to the collector are all configured here.
/// <para>
/// <b>Deliberately absent (deferred):</b>
/// <list type="bullet">
/// <item>SQL parameter masking / result-row limits / strict-match replay — these belong to dependency
/// mocking, which is not yet supported.</item>
/// </list>
/// </para>
/// </remarks>
public sealed class JakapilCaptureOptions
{
    /// <summary>Master on/off switch. When false, the middleware is a pure pass-through.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>The fraction of requests to capture, in the range [0, 1]. 1.0 = capture everything.</summary>
    public double SampleRate { get; set; } = 1.0;

    /// <summary>Bodies of this size (bytes) or smaller are captured inline; larger bodies are truncated at a JSON-safe boundary and marked as Truncated.</summary>
    public int MaxInlineBodyBytes { get; set; } = 1024 * 1024;

    /// <summary>The hard limit (bytes) on how much of a response body is buffered for capture.</summary>
    /// <remarks>
    /// The response itself always streams to the client unbuffered; only the capture copy is limited. When the
    /// limit is exceeded, the excess bytes are not buffered and the captured body is marked as Truncated — the
    /// client's response is never modified, delayed, or held in memory.
    /// </remarks>
    public int MaxCapturedResponseBytes { get; set; } = 2 * 1024 * 1024;

    /// <summary>
    /// Content types whose responses are captured with metadata only (status/headers/timing, no body):
    /// streaming or large-download media that must not be buffered (SSE, octet-stream downloads, gRPC).
    /// Matched by media-type prefix, case-insensitively.
    /// </summary>
    public string[] StreamingContentTypes { get; set; } =
    [
        "text/event-stream", "application/octet-stream", "application/grpc", "multipart/x-mixed-replace",
    ];

    /// <summary>The bounded capacity of the in-memory capture queue; under backpressure the oldest entries are dropped rather than blocking the request pipeline.</summary>
    public int QueueCapacity { get; set; } = 1024;

    /// <summary>Header names masked before capture (the value is replaced with <c>••••••••+last4</c>) — never sent to the collector in the clear.</summary>
    public string[] SensitiveHeaderNames { get; set; } =
    [
        "Authorization", "Cookie", "Set-Cookie", "Proxy-Authorization", "X-Api-Key",
    ];

    /// <summary>Header names treated as a custom correlation signal (see <c>CorrelationSignals.CustomCorrelationHeader</c>).</summary>
    public string[] CorrelationHeaderNames { get; set; } = ["X-Correlation-ID", "traceparent"];

    /// <summary>The root address of the collector to which captured interactions are sent (e.g. <c>http://localhost:5238</c>).
    /// If left empty, the export worker stays idle; the queue exists only with its bounded capacity (DropOldest).</summary>
    public string? CollectorUri { get; set; }

    /// <summary>The raw ingest key sent as-is to the collector in the <c>X-Jakapil-Key</c> header.</summary>
    public string? IngestKey { get; set; }

    /// <summary>The maximum number of interactions sent in a single export request (collector upper bound is 1000).</summary>
    public int ExportBatchMaxItems { get; set; } = 1000;

    /// <summary>How long (seconds) the export worker waits after at least one item appears in the queue, to coalesce
    /// the burst accumulated during that wake-up into a single batch.</summary>
    public int ExportFlushIntervalSeconds { get; set; } = 2;
}

/// <summary>The validator for <see cref="JakapilCaptureOptions"/> that runs at startup (host start, via <c>ValidateOnStart</c>).</summary>
/// <remarks>
/// It exists solely to catch configuration errors early and explicitly — it does not affect the request path,
/// and neither the middleware nor the export worker calls this validator at runtime.
/// </remarks>
internal sealed class JakapilCaptureOptionsValidator : IValidateOptions<JakapilCaptureOptions>
{
    /// <summary>Validates the given settings against the invariants; on violation, returns a failure with the reason.</summary>
    public ValidateOptionsResult Validate(string? name, JakapilCaptureOptions options)
    {
        var failures = new List<string>();

        if (options.SampleRate is < 0 or > 1)
        {
            failures.Add("The sampling rate (SampleRate) must be within the range [0, 1].");
        }

        if (options.QueueCapacity < 1)
        {
            failures.Add("The queue capacity (QueueCapacity) must be positive.");
        }

        if (options.ExportBatchMaxItems < 1)
        {
            failures.Add("The maximum export batch item count (ExportBatchMaxItems) must be positive.");
        }

        if (options.ExportFlushIntervalSeconds < 1)
        {
            failures.Add("The export flush interval (ExportFlushIntervalSeconds) must be positive.");
        }

        if (options.MaxInlineBodyBytes < 1)
        {
            failures.Add("The maximum inline captured body size (MaxInlineBodyBytes) must be positive.");
        }

        if (options.MaxCapturedResponseBytes < 1)
        {
            failures.Add("The maximum captured response body size (MaxCapturedResponseBytes) must be positive.");
        }

        if (options.Enabled)
        {
            var validCollectorUri = !string.IsNullOrWhiteSpace(options.CollectorUri)
                && Uri.TryCreate(options.CollectorUri, UriKind.Absolute, out _);
            if (!validCollectorUri)
            {
                failures.Add("When capture is enabled (Enabled=true), the collector address (CollectorUri) must be a valid, absolute URI.");
            }

            if (string.IsNullOrWhiteSpace(options.IngestKey))
            {
                failures.Add("When capture is enabled (Enabled=true), the ingest key (IngestKey) cannot be empty.");
            }
        }

        return failures.Count > 0
            ? ValidateOptionsResult.Fail(failures)
            : ValidateOptionsResult.Success;
    }
}
