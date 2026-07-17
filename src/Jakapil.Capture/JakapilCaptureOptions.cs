using System.Net;
using Jakapil.Capture.Anonymization;
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
    /// <remarks>This is Tier-1 masking and is ALWAYS applied regardless of <see cref="HeaderCaptureAllowlist"/>
    /// or <see cref="AnonymizedHeaderNames"/> (Phase 15c) — those are separate, additive controls; see their
    /// own remarks for how the three header pipelines relate.</remarks>
    public string[] SensitiveHeaderNames { get; set; } =
    [
        "Authorization", "Cookie", "Set-Cookie", "Proxy-Authorization", "X-Api-Key",
    ];

    /// <summary>
    /// Phase 15c (ADR-0002 §10) opt-in allowlist: when set (even to an empty array), ONLY headers whose name
    /// appears here are captured at all — every other header is omitted from the interaction entirely, never
    /// sent to the collector. When left <c>null</c> (the default), today's behavior is unchanged: every header
    /// is captured, with <see cref="SensitiveHeaderNames"/> masking applied to the sensitive ones.
    /// </summary>
    /// <remarks>
    /// The ADR's stated model for headers is allowlist-first ("only forward what you explicitly decided
    /// matters"), which is a stricter default than today's "capture everything except mask known-sensitive
    /// names". Flipping the DEFAULT to allowlist mode would be a behavior change that could silently drop
    /// headers a host currently relies on seeing in Jakapil — that is a product decision, not an engineering
    /// one, so this ships as an opt-in with the existing behavior preserved by default. See the phase report
    /// for the explicit question this raises.
    /// </remarks>
    public string[]? HeaderCaptureAllowlist { get; set; }

    /// <summary>
    /// Phase 15c (ADR-0002 §9) Tier-2: header NAMES whose VALUE is additionally run through field
    /// classification/fingerprinting by <see cref="Anonymization.Anonymizer"/> before egress (distinct from
    /// the Tier-1 masking above). Most headers are transport metadata, not business flow identifiers, so this
    /// is opt-in and empty by default — set it only for headers a host knows carry a correlatable business id
    /// (e.g. a custom idempotency-key header).
    /// </summary>
    public string[] AnonymizedHeaderNames { get; set; } = [];

    /// <summary>Header names treated as a custom correlation signal (see <c>CorrelationSignals.CustomCorrelationHeader</c>).</summary>
    public string[] CorrelationHeaderNames { get; set; } = ["X-Correlation-ID", "traceparent"];

    /// <summary>Phase 15c (ADR-0002): field anonymization configuration — key/version/scope/policy. See
    /// <see cref="Anonymization.AnonymizationOptions"/>.</summary>
    public AnonymizationOptions Anonymization { get; set; } = new();

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
            else if (Uri.TryCreate(options.CollectorUri, UriKind.Absolute, out var collectorUri)
                     && string.Equals(collectorUri.Scheme, "http", StringComparison.OrdinalIgnoreCase)
                     && !IsLoopbackHost(collectorUri.Host))
            {
                // Phase 15c-10: a plaintext (non-TLS) collector address is only acceptable for local
                // development against loopback; anywhere else it would ship captured traffic — anonymized or
                // not — over an unencrypted channel.
                failures.Add("The collector address (CollectorUri) uses http:// but its host is not localhost/loopback; use https:// outside local development.");
            }

            if (string.IsNullOrWhiteSpace(options.IngestKey))
            {
                failures.Add("When capture is enabled (Enabled=true), the ingest key (IngestKey) cannot be empty.");
            }
        }

        if (options.Anonymization.KeyVersion < 0)
        {
            failures.Add("The anonymization key version (Anonymization.KeyVersion) must be non-negative.");
        }

        return failures.Count > 0
            ? ValidateOptionsResult.Fail(failures)
            : ValidateOptionsResult.Success;
    }

    /// <summary>Reports whether a URI host is localhost or a loopback IP address (the only hosts a plaintext
    /// <c>http://</c> collector address is accepted for — Phase 15c-10).</summary>
    private static bool IsLoopbackHost(string host)
    {
        if (string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return IPAddress.TryParse(host, out var address) && IPAddress.IsLoopback(address);
    }
}
