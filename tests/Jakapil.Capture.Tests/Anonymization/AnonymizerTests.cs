using Jakapil.Capture;
using Jakapil.Capture.Anonymization;
using Jakapil.Capture.Contracts;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Jakapil.Capture.Tests.Anonymization;

/// <summary>End-to-end tests of <see cref="Anonymizer"/> against full <see cref="CapturedInteraction"/> DTOs —
/// the same seam <c>JakapilCaptureMiddleware</c> runs every interaction through (ADR-0002, Phase 15c).</summary>
public sealed class AnonymizerTests
{
    private static readonly byte[] Key = "integration-test-key"u8.ToArray();

    private static readonly AnonymizationOptions Options = new()
    {
        KeyVersion = 3,
        Scope = new AnonymizationScope { TenantId = "tenant-1", ProjectId = "project-1", Environment = "staging" },
    };

    private static CapturedInteraction BuildInteraction(
        string? requestBodyJson = null,
        IReadOnlyList<RouteParameter>? routeParameters = null,
        IReadOnlyDictionary<string, string>? queryParameters = null,
        string? responseBodyJson = null,
        string? locationHeader = null,
        bool requestBodyTruncated = false,
        IReadOnlyDictionary<string, string>? requestHeaders = null,
        string rawPath = "/api/orders")
    {
        return new CapturedInteraction
        {
            Id = Guid.NewGuid(),
            Timestamp = DateTimeOffset.UtcNow,
            DurationMs = 5,
            Correlation = new CorrelationSignals { ObservedAt = DateTimeOffset.UtcNow },
            Request = new CapturedRequest
            {
                Method = "POST",
                RawPath = rawPath,
                Headers = requestHeaders ?? new Dictionary<string, string>(),
                RouteParameters = routeParameters ?? [],
                QueryParameters = queryParameters,
                Body = requestBodyJson is null
                    ? null
                    : new CapturedBody { Text = requestBodyJson, ByteSize = requestBodyJson.Length, Truncated = requestBodyTruncated, Kind = BodyKind.Json },
            },
            Response = new CapturedResponse
            {
                StatusCode = 201,
                Headers = new Dictionary<string, string>(),
                Body = responseBodyJson is null
                    ? null
                    : new CapturedBody { Text = responseBodyJson, ByteSize = responseBodyJson.Length, Truncated = false, Kind = BodyKind.Json },
                LocationHeader = locationHeader,
            },
            Endpoint = new EndpointInfo { RouteTemplate = "/api/orders" },
        };
    }

    [Fact]
    public void Anonymize_NoKeyConfigured_ReturnsInteractionUnchanged_AndNeverSetsAnon()
    {
        var anonymizer = new Anonymizer(key: null, Options, []);
        var interaction = BuildInteraction(requestBodyJson: """{"email":"real@customer.com"}""");

        var result = anonymizer.Anonymize(interaction);

        Assert.Same(interaction, result);
        Assert.Null(result.Anon);
        Assert.Equal("""{"email":"real@customer.com"}""", result.Request.Body!.Text);
    }

    [Fact]
    public void DIConstructor_EnvironmentVariableUnset_LogsWarning_AndPassesThrough()
    {
        var logger = new RecordingLogger<Anonymizer>();
        var options = new JakapilCaptureOptions
        {
            Anonymization = new AnonymizationOptions { KeyEnvironmentVariable = "JAKAPIL_TEST_DEFINITELY_UNSET_" + Guid.NewGuid() },
        };

        var anonymizer = new Anonymizer(Microsoft.Extensions.Options.Options.Create(options), logger);
        var interaction = BuildInteraction(requestBodyJson: """{"email":"real@customer.com"}""");

        var result = anonymizer.Anonymize(interaction);

        Assert.Same(interaction, result);
        Assert.Contains(logger.Entries, e => e.Level == LogLevel.Warning);
    }

    [Fact]
    public void Anonymize_SetsAnonMetadata_WhenKeyConfigured()
    {
        var anonymizer = new Anonymizer(Key, Options, []);
        var interaction = BuildInteraction();

        var result = anonymizer.Anonymize(interaction);

        Assert.NotNull(result.Anon);
        Assert.Equal("hmac-sha256-v1", result.Anon!.Scheme);
        Assert.Equal(3, result.Anon.KeyVersion);
    }

    [Fact]
    public void Anonymize_SecretFieldInBody_ProducesTombstone_NeverFingerprint()
    {
        var anonymizer = new Anonymizer(Key, Options, []);
        var interaction = BuildInteraction(requestBodyJson: """{"password":"Gizli123!"}""");

        var result = anonymizer.Anonymize(interaction);

        Assert.Contains("jkp:tomb:s:password", result.Request.Body!.Text);
        Assert.DoesNotContain("Gizli123", result.Request.Body.Text);
        Assert.DoesNotContain("fp:", result.Request.Body.Text);
    }

    [Fact]
    public void Anonymize_PiiFieldInBody_ProducesSyntheticValue_NeverOriginal()
    {
        var anonymizer = new Anonymizer(Key, Options, []);
        var interaction = BuildInteraction(requestBodyJson: """{"email":"ayse.yilmaz@gercekfirma.com"}""");

        var result = anonymizer.Anonymize(interaction);

        Assert.DoesNotContain("gercekfirma.com", result.Request.Body!.Text);
        Assert.DoesNotContain("ayse.yilmaz", result.Request.Body.Text);
    }

    [Fact]
    public void Anonymize_SafeLiteralFieldInBody_PassesThroughUnchanged()
    {
        var anonymizer = new Anonymizer(Key, Options, []);
        var interaction = BuildInteraction(requestBodyJson: """{"currency":"TRY","quantity":2}""");

        var result = anonymizer.Anonymize(interaction);

        Assert.Equal("""{"currency":"TRY","quantity":2}""", result.Request.Body!.Text);
    }

    /// <summary>
    /// INV-A1 end-to-end: the customerId value embedded in a JSON body (as a quoted string) and the exact same
    /// value used as a route parameter (untyped transport) must fingerprint to the SAME digest, proving the
    /// cross-position correlation edge this whole design exists for.
    /// </summary>
    [Fact]
    public void Anonymize_SameIdValue_BodyStringAndRouteParameter_ProduceSameDigest()
    {
        const string customerId = "c9f14b2e-8a31-4f6d-9e02-77aa41b0c5d3";
        var anonymizer = new Anonymizer(Key, Options, []);

        var bodyInteraction = anonymizer.Anonymize(BuildInteraction(requestBodyJson: $$"""{"customerId":"{{customerId}}"}"""));
        var routeInteraction = anonymizer.Anonymize(BuildInteraction(routeParameters: [new RouteParameter("id", customerId, "Guid")]));

        var bodyEnvelope = ExtractFirstFingerprintEnvelope(bodyInteraction.Request.Body!.Text!);
        var routeEnvelope = routeInteraction.Request.RouteParameters[0].Value;

        var bodyDigest = bodyEnvelope.Split(':')[4];
        var routeDigest = routeEnvelope.Split(':')[4];

        Assert.Equal(bodyDigest, routeDigest);
        // jsonType differs (body quoted string -> "s" or "g"; route -> "u") even though the digest matches.
        Assert.Equal("g", bodyEnvelope.Split(':')[1]);
        Assert.Equal("u", routeEnvelope.Split(':')[1]);
    }

    [Fact]
    public void Anonymize_RawPath_ReplacesRouteParameterValue_ConsistentlyWithRouteParameters()
    {
        var anonymizer = new Anonymizer(Key, Options, []);
        var interaction = BuildInteraction(routeParameters: [new RouteParameter("id", "42", "int")], rawPath: "/api/orders/42");

        var result = anonymizer.Anonymize(interaction);

        var transformedRouteValue = result.Request.RouteParameters[0].Value;
        Assert.Contains(transformedRouteValue, result.Request.RawPath);
        Assert.DoesNotContain("/42", result.Request.RawPath);
    }

    [Fact]
    public void Anonymize_QueryParameters_TransformedAndQueryStringRebuiltFromThem()
    {
        var anonymizer = new Anonymizer(Key, Options, []);
        var interaction = BuildInteraction(queryParameters: new Dictionary<string, string> { ["categoryId"] = "55" });

        var result = anonymizer.Anonymize(interaction);

        var transformedValue = result.Request.QueryParameters!["categoryId"];
        Assert.NotEqual("55", transformedValue);
        Assert.Contains(Uri.EscapeDataString(transformedValue), result.Request.QueryString);
        Assert.DoesNotContain("=55", result.Request.QueryString);
    }

    [Fact]
    public void Anonymize_TruncatedJsonBody_WithholdsText_RatherThanLeakingPlaintext()
    {
        var anonymizer = new Anonymizer(Key, Options, []);
        var interaction = BuildInteraction(requestBodyJson: """{"email":"real@customer.com","incompl""", requestBodyTruncated: true);

        var result = anonymizer.Anonymize(interaction);

        Assert.Null(result.Request.Body!.Text);
    }

    [Fact]
    public void Anonymize_InvalidJsonBody_WithholdsText_RatherThanLeakingPlaintext()
    {
        var anonymizer = new Anonymizer(Key, Options, []);
        var interaction = BuildInteraction(requestBodyJson: "not valid json {{{");

        var result = anonymizer.Anonymize(interaction);

        Assert.Null(result.Request.Body!.Text);
    }

    [Fact]
    public void Anonymize_LocationHeader_LastSegmentIdentifierShaped_IsFingerprinted()
    {
        var anonymizer = new Anonymizer(Key, Options, []);
        var interaction = BuildInteraction(locationHeader: "/api/customers/c9f14b2e-8a31-4f6d-9e02-77aa41b0c5d3");

        var result = anonymizer.Anonymize(interaction);

        Assert.DoesNotContain("c9f14b2e-8a31-4f6d-9e02-77aa41b0c5d3", result.Response.LocationHeader);
        Assert.Contains("fp:", result.Response.LocationHeader);
    }

    [Fact]
    public void Anonymize_AnonymizedHeaderAllowlist_TransformsOnlyListedHeader()
    {
        var anonymizer = new Anonymizer(Key, Options, ["X-Idempotency-Key"]);
        var interaction = BuildInteraction(requestHeaders: new Dictionary<string, string>
        {
            ["X-Idempotency-Key"] = "order-4821",
            ["X-Other-Header"] = "unchanged-value",
        });

        var result = anonymizer.Anonymize(interaction);

        Assert.NotEqual("order-4821", result.Request.Headers["X-Idempotency-Key"]);
        Assert.Equal("unchanged-value", result.Request.Headers["X-Other-Header"]);
    }

    private static string ExtractFirstFingerprintEnvelope(string json)
    {
        var index = json.IndexOf("fp:", StringComparison.Ordinal);
        Assert.True(index >= 0, $"No fingerprint envelope found in '{json}'.");
        var end = json.IndexOf('"', index);
        return end >= 0 ? json[index..end] : json[index..];
    }

    /// <summary>Minimal in-memory <see cref="ILogger{T}"/> that records every log call, used to verify the
    /// pass-through-mode startup warning without depending on any real logging provider.</summary>
    private sealed class RecordingLogger<T> : ILogger<T>
    {
        public readonly List<(LogLevel Level, string Message)> Entries = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            Entries.Add((logLevel, formatter(state, exception)));
        }
    }
}
