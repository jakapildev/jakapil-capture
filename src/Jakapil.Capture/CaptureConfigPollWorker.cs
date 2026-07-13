using System.Net.Http.Json;
using System.Text.Json;
using Jakapil.Capture.Contracts;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Jakapil.Capture;

/// <summary>
/// Background worker that periodically (Phase 14 M4) polls the collector's <c>GET /ingest/config</c> endpoint
/// and reflects the environment's remote capture on/off state and revision into <see cref="CaptureRuntimeState"/>.
/// </summary>
/// <remarks>
/// <b>Harmlessness guarantee.</b> If the config endpoint is UNREACHABLE (network error, error status, unparseable
/// body) the last known state is RETAINED — the error is only logged (at debug level) and the host request is
/// never affected in any way; this worker runs as a <see cref="BackgroundService"/> on a separate background task,
/// entirely outside the main request pipeline. The poll interval follows the server-returned
/// <c>pollIntervalSeconds</c>; until the first successful poll (or if none ever succeeds) <see cref="DefaultPollInterval"/>
/// (15 s) is used — that is the target maximum propagation delay (the M4 acceptance criterion). When
/// <c>Enabled=false</c> locally (the SDK's hard off baseline) polling is pointless — <see cref="ExecuteAsync"/> exits
/// early in that case (the same "stay idle when configuration is missing/pointless" pattern as <see cref="ExportWorker"/>).
/// </remarks>
internal sealed class CaptureConfigPollWorker : BackgroundService
{
    /// <summary>The named <see cref="IHttpClientFactory"/> client used for poll requests.</summary>
    internal const string HttpClientName = "jakapil-capture-config-poll";

    /// <summary>The initial/fallback poll interval used when no successful response has ever been received from the server.</summary>
    internal static readonly TimeSpan DefaultPollInterval = TimeSpan.FromSeconds(15);

    private static readonly JsonSerializerOptions WireJson = new(JsonSerializerDefaults.Web);

    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IOptions<JakapilCaptureOptions> _options;
    private readonly CaptureRuntimeState _state;
    private readonly ICapturedInteractionQueue _queue;
    private readonly TimeProvider _timeProvider;
    private readonly ILogger<CaptureConfigPollWorker> _logger;

    /// <summary>Constructs the worker with the HttpClient factory, options, shared runtime state, capture queue,
    /// time source and logger.</summary>
    public CaptureConfigPollWorker(
        IHttpClientFactory httpClientFactory,
        IOptions<JakapilCaptureOptions> options,
        CaptureRuntimeState state,
        ICapturedInteractionQueue queue,
        TimeProvider timeProvider,
        ILogger<CaptureConfigPollWorker> logger)
    {
        _httpClientFactory = httpClientFactory;
        _options = options;
        _state = state;
        _queue = queue;
        _timeProvider = timeProvider;
        _logger = logger;
    }

    /// <summary>
    /// If local capture is off (<c>Enabled=false</c>) or configuration is missing (no collector address/ingest
    /// key) the worker stays idle without polling at all. Otherwise it polls in a continuous loop, adjusting the
    /// interval to what the server tells it; unexpected errors do not break the loop, they are only logged (the
    /// last known state is retained).
    /// </summary>
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var opts = _options.Value;
        if (!opts.Enabled)
        {
            return;
        }

        if (string.IsNullOrWhiteSpace(opts.CollectorUri) || string.IsNullOrWhiteSpace(opts.IngestKey))
        {
            _logger.LogError("Jakapil: collector address/key missing; capture config polling disabled");
            return;
        }

        var pollInterval = DefaultPollInterval;

        while (!stoppingToken.IsCancellationRequested)
        {
            pollInterval = await PollOnceAsync(opts, pollInterval, stoppingToken);

            try
            {
                await Task.Delay(pollInterval, _timeProvider, stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
    }

    /// <summary>
    /// Polls the config endpoint once and applies the result to the runtime state. On failure (unsuccessful status
    /// code, network error, unparseable body) it returns WITHOUT CHANGING the current <paramref name="currentInterval"/>
    /// and RETAINS the state — returning the next interval for the caller to use.
    /// </summary>
    internal async Task<TimeSpan> PollOnceAsync(JakapilCaptureOptions opts, TimeSpan currentInterval, CancellationToken cancellationToken)
    {
        try
        {
            var client = _httpClientFactory.CreateClient(HttpClientName);
            var url = opts.CollectorUri!.TrimEnd('/') + "/ingest/config";

            var request = new HttpRequestMessage(HttpMethod.Get, url);
            request.Headers.Add("X-Jakapil-Key", opts.IngestKey);

            var response = await client.SendAsync(request, cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                _logger.LogDebug("Jakapil: config poll returned {StatusCode}; last known capture state retained", response.StatusCode);
                return currentInterval;
            }

            var config = await response.Content.ReadFromJsonAsync<CaptureConfigResponse>(WireJson, cancellationToken);
            if (config is null)
            {
                return currentInterval;
            }

            ApplyConfig(config);

            return config.PollIntervalSeconds > 0 ? TimeSpan.FromSeconds(config.PollIntervalSeconds) : currentInterval;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Jakapil: config poll failed; last known capture state retained, host request unaffected");
            return currentInterval;
        }
    }

    /// <summary>
    /// Writes the new server-provided state into the runtime state; on an enabled→disabled transition (only in this
    /// direction) it discards the unsent interactions waiting in the queue (<see cref="ICapturedInteractionQueue.Clear"/>)
    /// — the queue of a capture that has been turned off is never sent again.
    /// </summary>
    private void ApplyConfig(CaptureConfigResponse config)
    {
        var wasEnabled = _state.Enabled;
        _state.SetEnabled(config.Enabled);

        if (wasEnabled && !config.Enabled)
        {
            _queue.Clear();
        }
    }
}
