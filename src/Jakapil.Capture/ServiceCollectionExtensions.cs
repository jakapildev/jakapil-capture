using Jakapil.Capture.Anonymization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Jakapil.Capture;

/// <summary>
/// DI registration of the Jakapil core capture pipeline: options, a bounded in-memory queue, the process-local
/// token-source registry, the background export worker, and its collector HttpClient.
/// </summary>
/// <remarks>
/// <b>Deferred (not registered here):</b> dependency recording/replay stubs belong to mocking, which is not
/// yet supported.
/// </remarks>
public static class ServiceCollectionExtensions
{
    /// <summary>Registers Jakapil core request/response capture: wires the options, the bounded queue, the
    /// process-local token registry that stores no raw tokens (hash-keyed), and the background export worker
    /// that transports the queue to the collector + its named HttpClient.</summary>
    public static IServiceCollection AddJakapilCapture(this IServiceCollection services, Action<JakapilCaptureOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(configure);

        services.AddOptions<JakapilCaptureOptions>().Configure(configure).ValidateOnStart();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IValidateOptions<JakapilCaptureOptions>, JakapilCaptureOptionsValidator>());

        services.AddSingleton<CapturedInteractionQueue>();
        services.AddSingleton<ICapturedInteractionQueue>(sp => sp.GetRequiredService<CapturedInteractionQueue>());

        services.AddSingleton<IAuthTokenRegistry, AuthTokenRegistry>();

        services.AddSingleton<IAnonymizer, Anonymizer>();

        services.AddHttpClient(CaptureExporter.HttpClientName);
        services.AddSingleton<CaptureExporter>();
        services.TryAddSingleton(TimeProvider.System);
        services.AddHostedService<ExportWorker>();

        services.AddSingleton<CaptureRuntimeState>();
        services.AddSingleton<ICaptureRuntimeState>(sp => sp.GetRequiredService<CaptureRuntimeState>());
        services.AddHttpClient(CaptureConfigPollWorker.HttpClientName);
        services.AddHostedService<CaptureConfigPollWorker>();

        return services;
    }

    /// <summary>Registers Jakapil capture directly with an ingest key and collector address; the optional <paramref name="configure"/> is applied for additional settings.</summary>
    public static IServiceCollection AddJakapilCapture(this IServiceCollection services, string ingestKey, string collectorUri, Action<JakapilCaptureOptions>? configure = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(ingestKey);
        ArgumentException.ThrowIfNullOrWhiteSpace(collectorUri);

        return services.AddJakapilCapture(options =>
        {
            options.IngestKey = ingestKey;
            options.CollectorUri = collectorUri;
            configure?.Invoke(options);
        });
    }
}
