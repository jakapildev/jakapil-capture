using Jakapil.Capture.Contracts;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Jakapil.Capture;

/// <summary>
/// Background worker that drains the in-memory capture queue and forwards the accumulated interactions to the
/// collector via <see cref="CaptureExporter"/>.
/// </summary>
/// <remarks>
/// It is the queue consumer: the middleware only writes, the draining responsibility lives here; the HTTP/gzip
/// transport is delegated to <see cref="CaptureExporter"/>. If the transport fails the batch is lossy by design —
/// it is not re-queued; the queue itself is already bounded with DropOldest, so the target application never
/// accumulates unbounded memory even when the collector is unreachable.
/// </remarks>
internal sealed class ExportWorker : BackgroundService
{
    private readonly CapturedInteractionQueue _queue;
    private readonly CaptureExporter _exporter;
    private readonly IOptions<JakapilCaptureOptions> _options;
    private readonly TimeProvider _timeProvider;
    private readonly ILogger<ExportWorker> _logger;

    /// <summary>Constructs the worker with the queue, exporter, options, time source and logger.</summary>
    public ExportWorker(
        CapturedInteractionQueue queue,
        CaptureExporter exporter,
        IOptions<JakapilCaptureOptions> options,
        TimeProvider timeProvider,
        ILogger<ExportWorker> logger)
    {
        _queue = queue;
        _exporter = exporter;
        _options = options;
        _timeProvider = timeProvider;
        _logger = logger;
    }

    /// <summary>
    /// If configuration is missing (no collector address or ingest key) the worker stays idle after a single error
    /// log — the queue continues to exist only with its DropOldest bound.
    /// </summary>
    /// <remarks>
    /// Otherwise: it waits until at least one item appears in the queue, gathers the burst that accumulates during
    /// that wake-up over a short flush interval, then drains and sends the batch. Unexpected errors do not break the
    /// loop, they are only logged.
    /// </remarks>
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var opts = _options.Value;
        if (string.IsNullOrWhiteSpace(opts.CollectorUri) || string.IsNullOrWhiteSpace(opts.IngestKey))
        {
            _logger.LogError("Jakapil: collector address/key missing; capture export disabled");
            return;
        }

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                if (!await _queue.Reader.WaitToReadAsync(stoppingToken))
                {
                    break;
                }

                try
                {
                    await Task.Delay(TimeSpan.FromSeconds(Math.Max(0, opts.ExportFlushIntervalSeconds)), _timeProvider, stoppingToken);
                }
                catch (OperationCanceledException)
                {
                }

                await FlushBatchAsync(stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Jakapil: unexpected error in the export loop; worker continues running");
            }
        }
    }

    /// <summary>
    /// Drains the interactions waiting in the queue (at most <see cref="JakapilCaptureOptions.ExportBatchMaxItems"/>)
    /// without blocking and sends them to the collector via <see cref="CaptureExporter"/>.
    /// </summary>
    /// <remarks>
    /// If configuration is missing it returns 0 without draining any items. It is exposed as a separate internal
    /// method so that it is testable.
    /// </remarks>
    internal async Task<int> FlushBatchAsync(CancellationToken cancellationToken)
    {
        var opts = _options.Value;
        if (string.IsNullOrWhiteSpace(opts.CollectorUri) || string.IsNullOrWhiteSpace(opts.IngestKey))
        {
            return 0;
        }

        var batch = new List<CapturedInteraction>();
        while (batch.Count < opts.ExportBatchMaxItems && _queue.Reader.TryRead(out var item))
        {
            batch.Add(item);
        }

        if (batch.Count == 0)
        {
            return 0;
        }

        return await _exporter.SendBatchAsync(batch, cancellationToken);
    }
}
