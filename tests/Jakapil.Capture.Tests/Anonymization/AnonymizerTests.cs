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
        string rawPath = "/api/orders",
        IdentityInfo? identity = null,
        CorrelationSignals? correlation = null,
        AuthBinding? auth = null)
    {
        return new CapturedInteraction
        {
            Id = Guid.NewGuid(),
            Timestamp = DateTimeOffset.UtcNow,
            DurationMs = 5,
            Correlation = correlation ?? new CorrelationSignals { ObservedAt = DateTimeOffset.UtcNow },
            Identity = identity,
            Auth = auth,
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
        Assert.Equal("hmac-sha256-v2", result.Anon!.Scheme);
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
    /// End-to-end regression test for the field bug report (v1.2.0): the real eShop response body,
    /// <c>GET /api/catalog-types</c> → <c>{ "catalogTypes": [ { "name": "Mug" }, { "name": "T-Shirt" } ] }</c>,
    /// must pass through with the category names UNCHANGED. Before this fix, bare <c>name</c> was classified
    /// exactly like <c>fullName</c> and every category label was rewritten to a synthetic person name (e.g.
    /// "Sage Blake"), so a scenario built from this capture asserted the wrong literal on every replay against
    /// the live API — a guaranteed false regression.
    /// </summary>
    [Fact]
    public void Anonymize_GenericNameField_UnderNonPersonArrayContext_PassesThroughUnchanged()
    {
        var anonymizer = new Anonymizer(Key, Options, []);
        var interaction = BuildInteraction(
            responseBodyJson: """{"catalogTypes":[{"id":1,"name":"Mug"},{"id":2,"name":"T-Shirt"}]}""");

        var result = anonymizer.Anonymize(interaction);

        Assert.Contains("\"name\":\"Mug\"", result.Response.Body!.Text);
        Assert.Contains("\"name\":\"T-Shirt\"", result.Response.Body.Text);
    }

    /// <summary>Counter-example to the test above: the SAME generic <c>name</c> field, but nested under a
    /// person-context object (<c>customer</c>), still synthesizes — proving the fix is context-sensitive, not a
    /// blanket "name is never PII" regression.</summary>
    [Fact]
    public void Anonymize_GenericNameField_UnderCustomerContext_ProducesSyntheticValue()
    {
        var anonymizer = new Anonymizer(Key, Options, []);
        var interaction = BuildInteraction(requestBodyJson: """{"customer":{"name":"Ayşe Yılmaz"}}""");

        var result = anonymizer.Anonymize(interaction);

        Assert.DoesNotContain("Ayşe", result.Request.Body!.Text);
        Assert.DoesNotContain("Yılmaz", result.Request.Body.Text);
    }

    /// <summary>A root-level, unnamespaced <c>name</c> (no enclosing object) also passes through unchanged —
    /// same rule as the array case above, just with no parent context at all rather than a non-person one.</summary>
    [Fact]
    public void Anonymize_GenericNameField_AtDocumentRoot_PassesThroughUnchanged()
    {
        var anonymizer = new Anonymizer(Key, Options, []);
        var interaction = BuildInteraction(requestBodyJson: """{"name":"Widget"}""");

        var result = anonymizer.Anonymize(interaction);

        Assert.Equal("""{"name":"Widget"}""", result.Request.Body!.Text);
    }

    /// <summary>
    /// Lead-review regression (post-v1.2.0 fix): plural REST collection endpoints
    /// (<c>GET /api/users</c> → <c>{ "users": [ { "name": "..." } ] }</c>) are the single most common shape a
    /// person record appears in, and <see cref="FieldNameRules.Normalize"/> alone does not singularize —
    /// without <see cref="FieldNameRules.HasPersonContext"/>'s singular-candidate matching, the parent word
    /// <c>users</c> would not match the singular <c>user</c> entry in
    /// <see cref="FieldNameRules.PersonContextNames"/>, and a real name would leak as plaintext
    /// <see cref="FieldClass.SafeLiteral"/>. This is the end-to-end proof (through the real JSON walk, not just
    /// the classifier unit), covering the three suffix shapes: plain <c>-s</c> (<c>users</c>), <c>-s</c> again
    /// with a longer stem (<c>customers</c>), and the double-<c>s</c>-adjacent (<c>employees</c>).
    /// </summary>
    [Theory]
    [InlineData("users")]
    [InlineData("customers")]
    [InlineData("employees")]
    public void Anonymize_GenericNameField_UnderPluralPersonCollection_ProducesSyntheticValue(string collectionFieldName)
    {
        var anonymizer = new Anonymizer(Key, Options, []);
        var interaction = BuildInteraction(
            requestBodyJson: $$"""{"{{collectionFieldName}}":[{"name":"Ahmet Yılmaz"}]}""");

        var result = anonymizer.Anonymize(interaction);

        Assert.DoesNotContain("Ahmet", result.Request.Body!.Text);
        Assert.DoesNotContain("Yılmaz", result.Request.Body.Text);
    }

    /// <summary>Counter-example to the plural-collection test above: <c>companies</c> singularizes to
    /// <c>company</c>, which is deliberately NOT in <see cref="FieldNameRules.PersonContextNames"/> (a company
    /// is not a person) — proving the singularization fix widens matching for real person collections without
    /// making every plural parent match indiscriminately.</summary>
    [Fact]
    public void Anonymize_GenericNameField_UnderPluralNonPersonCollection_PassesThroughUnchanged()
    {
        var anonymizer = new Anonymizer(Key, Options, []);
        var interaction = BuildInteraction(requestBodyJson: """{"companies":[{"name":"Acme Corp"}]}""");

        var result = anonymizer.Anonymize(interaction);

        Assert.Equal("""{"companies":[{"name":"Acme Corp"}]}""", result.Request.Body!.Text);
    }

    /// <summary>Non-regression check for the original bug report's exact shape, re-asserted here alongside the
    /// new plural-collection tests so the two live side by side and neither can silently regress the other.</summary>
    [Fact]
    public void Anonymize_GenericNameField_UnderCatalogTypesArray_PassesThroughUnchanged()
    {
        var anonymizer = new Anonymizer(Key, Options, []);
        var interaction = BuildInteraction(requestBodyJson: """{"catalogTypes":[{"name":"Mug"}]}""");

        var result = anonymizer.Anonymize(interaction);

        Assert.Equal("""{"catalogTypes":[{"name":"Mug"}]}""", result.Request.Body!.Text);
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

    // ---- v1.2.0 type-preserving anonymization ------------------------------------------------------------
    // Real end-to-end repro (see task report): PageSize=10&PageIndex=0 query parameters, unrecognized field
    // names, hit the unknown-field fail-safe (SyntheticPii) and used to synthesize to alphanumeric TEXT
    // ("synthetic-77598c5712fd"), which the target's model binder rejected (400). Classification is unchanged
    // (still SyntheticPii, per the fail-safe) — only the replacement's TEXT shape now still parses as a number.

    [Fact]
    public void Anonymize_NumericQueryParameter_UnrecognizedFieldName_SyntheticValueStillParsesAsNumber()
    {
        // "BatchCount" is deliberately NOT one of the recognized pagination/counter names (GIZLILIK-2/G-1-1) —
        // this test is about the general unknown-field fail-safe's shape preservation, not the pagination
        // SafeLiteral exception (covered separately below).
        var anonymizer = new Anonymizer(Key, Options, []);
        var interaction = BuildInteraction(queryParameters: new Dictionary<string, string> { ["BatchCount"] = "10" });

        var result = anonymizer.Anonymize(interaction);

        var transformed = result.Request.QueryParameters!["BatchCount"];
        Assert.NotEqual("10", transformed);
        Assert.True(long.TryParse(transformed, out _), $"Synthetic query value '{transformed}' does not parse as a number.");
    }

    [Fact]
    public void Anonymize_BooleanShapedQueryParameter_UnrecognizedFieldName_SyntheticValueStillParsesAsBoolean()
    {
        var anonymizer = new Anonymizer(Key, Options, []);
        var interaction = BuildInteraction(queryParameters: new Dictionary<string, string> { ["IsArchived"] = "true" });

        var result = anonymizer.Anonymize(interaction);

        var transformed = result.Request.QueryParameters!["IsArchived"];
        Assert.True(transformed is "true" or "false", $"Synthetic query value '{transformed}' is not a boolean literal.");
    }

    [Fact]
    public void Anonymize_QueryParameterSynthesis_IsDeterministic_SameInputSameOutput()
    {
        var anonymizer = new Anonymizer(Key, Options, []);
        var first = anonymizer.Anonymize(BuildInteraction(queryParameters: new Dictionary<string, string> { ["BatchCount"] = "10" }));
        var second = anonymizer.Anonymize(BuildInteraction(queryParameters: new Dictionary<string, string> { ["BatchCount"] = "10" }));

        Assert.Equal(first.Request.QueryParameters!["BatchCount"], second.Request.QueryParameters!["BatchCount"]);
    }

    // ---- v1.3.1 pagination/counter transport SafeLiteral exception (GIZLILIK-2/G-1-1) -------------------
    // Real end-to-end repro (see task report): GET /api/catalog-items?PageSize=10&PageIndex=0 anonymized into
    // ?PageSize=35&PageIndex=1 — a DIFFERENT number — because neither name was in the built-in SafeLiteral
    // allowlist, so both fell to the unknown-field fail-safe (SyntheticPii, shape-preserved but still a
    // different value). This corrupts the request's meaning, not just its identity, producing a scenario that
    // fails deterministically against the live API.

    [Theory]
    [InlineData("PageSize", "10")]
    [InlineData("PageIndex", "0")]
    [InlineData("pagesize", "10")]
    [InlineData("page_size", "10")]
    [InlineData("page[size]", "10")]
    [InlineData("$top", "25")]
    [InlineData("offset", "1000000")]
    public void Anonymize_RecognizedPaginationCounterQueryParameter_NumericValue_PassesThroughUnchanged(string fieldName, string value)
    {
        var anonymizer = new Anonymizer(Key, Options, []);
        var interaction = BuildInteraction(queryParameters: new Dictionary<string, string> { [fieldName] = value });

        var result = anonymizer.Anonymize(interaction);

        Assert.Equal(value, result.Request.QueryParameters![fieldName]);
    }

    [Fact]
    public void Anonymize_PaginationCounterQueryParameter_NonNumericValue_ShapeGateBlocksException_StillSynthesized()
    {
        // Name matches ("pageSize"), but the value does not look numeric at all — the shape gate must block the
        // SafeLiteral exception, so a name/value mismatch can never be used to sneak free text through unmasked.
        var anonymizer = new Anonymizer(Key, Options, []);
        var interaction = BuildInteraction(queryParameters: new Dictionary<string, string> { ["pageSize"] = "ahmet@x.com" });

        var result = anonymizer.Anonymize(interaction);

        Assert.NotEqual("ahmet@x.com", result.Request.QueryParameters!["pageSize"]);
    }

    [Fact]
    public void Anonymize_IdentifierQueryParameter_StillFingerprinted_NoRegressionFromPaginationException()
    {
        var anonymizer = new Anonymizer(Key, Options, []);
        var interaction = BuildInteraction(queryParameters: new Dictionary<string, string> { ["userId"] = "12345" });

        var result = anonymizer.Anonymize(interaction);

        Assert.StartsWith("fp:", result.Request.QueryParameters!["userId"]);
    }

    [Fact]
    public void Anonymize_PageSizeStringInJsonBody_StillSynthesized_ExceptionIsTransportOnly()
    {
        // The pagination/counter SafeLiteral exception is scoped to TransformTransportValue (route/query/header)
        // only — a JSON body leaf with the exact same field name must be unaffected (no regression on body
        // classification, and no accidental widening of the global SafeLiteralFieldNames allowlist).
        var anonymizer = new Anonymizer(Key, Options, []);
        var interaction = BuildInteraction(requestBodyJson: """{"pageSize":"10"}""");

        var result = anonymizer.Anonymize(interaction);

        Assert.DoesNotContain("\"pageSize\":\"10\"", result.Request.Body!.Text);
    }

    [Theory]
    [InlineData("page", "2")]
    [InlineData("limit", "50")]
    public void Anonymize_PreExistingSafeLiteralCounterName_NoRegression(string fieldName, string value)
    {
        var anonymizer = new Anonymizer(Key, Options, []);
        var interaction = BuildInteraction(queryParameters: new Dictionary<string, string> { [fieldName] = value });

        var result = anonymizer.Anonymize(interaction);

        Assert.Equal(value, result.Request.QueryParameters![fieldName]);
    }

    [Fact]
    public void Anonymize_PageSizeQueryParameter_FieldPolicyOverride_WinsOverPaginationException()
    {
        var options = new AnonymizationOptions
        {
            KeyVersion = Options.KeyVersion,
            Scope = Options.Scope,
            FieldPolicy = new Dictionary<string, FieldClass>(StringComparer.OrdinalIgnoreCase) { ["pageSize"] = FieldClass.SecretTombstone },
        };
        var anonymizer = new Anonymizer(Key, options, []);
        var interaction = BuildInteraction(queryParameters: new Dictionary<string, string> { ["pageSize"] = "10" });

        var result = anonymizer.Anonymize(interaction);

        Assert.Contains("jkp:tomb:", result.Request.QueryParameters!["pageSize"]);
    }

    [Fact]
    public void Anonymize_JsonBodyNumberField_ForcedToSyntheticPiiByFieldPolicy_ProducesJsonNumber_NotJsonString()
    {
        var options = new AnonymizationOptions
        {
            KeyVersion = Options.KeyVersion,
            Scope = Options.Scope,
            FieldPolicy = new Dictionary<string, FieldClass>(StringComparer.OrdinalIgnoreCase) { ["amount"] = FieldClass.SyntheticPii },
        };
        var anonymizer = new Anonymizer(Key, options, []);
        var interaction = BuildInteraction(requestBodyJson: """{"amount":250}""");

        var result = anonymizer.Anonymize(interaction);

        using var document = System.Text.Json.JsonDocument.Parse(result.Request.Body!.Text!);
        var amount = document.RootElement.GetProperty("amount");
        Assert.Equal(System.Text.Json.JsonValueKind.Number, amount.ValueKind);
        Assert.NotEqual(250, amount.GetInt32());
    }

    [Fact]
    public void Anonymize_JsonBodyIntegerField_ForcedToSyntheticPiiByFieldPolicy_StaysIntegral_NoDecimalPoint()
    {
        var options = new AnonymizationOptions
        {
            KeyVersion = Options.KeyVersion,
            Scope = Options.Scope,
            FieldPolicy = new Dictionary<string, FieldClass>(StringComparer.OrdinalIgnoreCase) { ["amount"] = FieldClass.SyntheticPii },
        };
        var anonymizer = new Anonymizer(Key, options, []);
        var interaction = BuildInteraction(requestBodyJson: """{"amount":250}""");

        var result = anonymizer.Anonymize(interaction);

        using var document = System.Text.Json.JsonDocument.Parse(result.Request.Body!.Text!);
        var amount = document.RootElement.GetProperty("amount");
        Assert.Equal(System.Text.Json.JsonValueKind.Number, amount.ValueKind);
        // Must parse as a whole number (int) — the original had no fractional part, so the synthetic
        // replacement must not introduce one either.
        Assert.True(amount.TryGetInt64(out _), "Synthetic replacement for an integer field is not itself an integer.");
    }

    [Fact]
    public void Anonymize_JsonBodyDecimalField_ForcedToSyntheticPiiByFieldPolicy_StaysDecimal()
    {
        var options = new AnonymizationOptions
        {
            KeyVersion = Options.KeyVersion,
            Scope = Options.Scope,
            FieldPolicy = new Dictionary<string, FieldClass>(StringComparer.OrdinalIgnoreCase) { ["price"] = FieldClass.SyntheticPii },
        };
        var anonymizer = new Anonymizer(Key, options, []);
        var interaction = BuildInteraction(requestBodyJson: """{"price":19.99}""");

        var result = anonymizer.Anonymize(interaction);

        using var document = System.Text.Json.JsonDocument.Parse(result.Request.Body!.Text!);
        var price = document.RootElement.GetProperty("price");
        Assert.Equal(System.Text.Json.JsonValueKind.Number, price.ValueKind);
        Assert.NotEqual(19.99, price.GetDouble());
    }

    [Fact]
    public void Anonymize_SecretFieldInBody_TombstoneBehaviorUnchanged_ByTypePreservingFix()
    {
        // Non-regression: the type-preservation fix must not touch SecretTombstone's envelope grammar — a
        // numeric secret (explicitly policy-classified, since no built-in secret name is number-shaped in
        // practice) still tombstones to the textual `jkp:tomb:n:...` marker, NOT a raw/type-preserved number
        // (INV-A3: a tombstone carries zero information, including the original type's plausibility).
        var options = new AnonymizationOptions
        {
            KeyVersion = Options.KeyVersion,
            Scope = Options.Scope,
            FieldPolicy = new Dictionary<string, FieldClass>(StringComparer.OrdinalIgnoreCase) { ["pin"] = FieldClass.SecretTombstone },
        };
        var anonymizer = new Anonymizer(Key, options, []);
        var interaction = BuildInteraction(requestBodyJson: """{"password":"Gizli123!","pin":4821}""");

        var result = anonymizer.Anonymize(interaction);

        Assert.Contains("jkp:tomb:s:password", result.Request.Body!.Text);
        Assert.Contains("jkp:tomb:n:pin", result.Request.Body.Text);
        Assert.DoesNotContain("Gizli123", result.Request.Body.Text);
        Assert.DoesNotContain("4821", result.Request.Body.Text);
    }

    /// <summary>
    /// Defect 2 repro (see task report): ADR-0003 §5's FlowFingerprint passthrough on replay used to rewrite a
    /// live numeric id into a JSON STRING (<c>{"id":"1"}</c> instead of <c>{"id":1}</c>), breaking a schema
    /// assertion expecting <c>Number</c>. The passthrough value is the untouched live value — it must be written
    /// back as the exact same JSON type it already is.
    /// </summary>
    [Fact]
    public void MaskReplayResponseBody_FlowFingerprintNumericId_PassthroughStaysJsonNumber_NotJsonString()
    {
        var anonymizer = new Anonymizer(Key, Options, []);
        var body = System.Text.Encoding.UTF8.GetBytes("""{"catalogTypes":[{"id":1,"name":"Mug"}]}""");

        var masked = anonymizer.MaskReplayResponseBody(body, "application/json; charset=utf-8");

        Assert.NotNull(masked);
        using var document = System.Text.Json.JsonDocument.Parse(masked.Body);
        var idElement = document.RootElement.GetProperty("catalogTypes")[0].GetProperty("id");
        Assert.Equal(System.Text.Json.JsonValueKind.Number, idElement.ValueKind);
        Assert.Equal(1, idElement.GetInt32());
    }

    [Fact]
    public void MaskReplayResponseBody_FlowFingerprintDecimalId_PassthroughStaysJsonNumber()
    {
        var anonymizer = new Anonymizer(Key, Options, []);
        var body = System.Text.Encoding.UTF8.GetBytes("""{"customerId":42.5}""");

        var masked = anonymizer.MaskReplayResponseBody(body, "application/json");

        Assert.NotNull(masked);
        using var document = System.Text.Json.JsonDocument.Parse(masked.Body);
        var idElement = document.RootElement.GetProperty("customerId");
        Assert.Equal(System.Text.Json.JsonValueKind.Number, idElement.ValueKind);
        Assert.Equal(42.5, idElement.GetDouble());
    }

    // ---- v1.2.0 RunCredential (ADR-0003 §5 revision, WHY #1) --------------------------------------------------
    // A live login-response `token` used to come back tombstoned (`jkp:tomb:s:token`) — the Runner cannot chain
    // an unusable marker into the next step's Authorization header, so no authenticated scenario could ever run.

    [Fact]
    public void MaskReplayResponseBody_TokenField_PassesThroughLive_NotTombstoned_AndDeclaredInLiveJsonPaths()
    {
        var anonymizer = new Anonymizer(Key, Options, []);
        var body = System.Text.Encoding.UTF8.GetBytes("""{"token":"live-session-token-abc123"}""");

        var masked = anonymizer.MaskReplayResponseBody(body, "application/json");

        Assert.NotNull(masked);
        var text = System.Text.Encoding.UTF8.GetString(masked.Body);
        Assert.Contains("\"token\":\"live-session-token-abc123\"", text);
        Assert.DoesNotContain("jkp:tomb:", text);
        Assert.Equal(["$.token"], masked.LiveJsonPaths);
    }

    [Fact]
    public void MaskReplayResponseBody_PasswordField_StaysTombstoned_NeverPassesThroughLive()
    {
        // Decision B, explicit exclusion: "password" is an INPUT secret, never a run-issued credential — it
        // must never pass through even though it sits right next to `token` in SecretFieldNames.
        var anonymizer = new Anonymizer(Key, Options, []);
        var body = System.Text.Encoding.UTF8.GetBytes("""{"password":"Gizli123!","token":"live-token"}""");

        var masked = anonymizer.MaskReplayResponseBody(body, "application/json");

        Assert.NotNull(masked);
        var text = System.Text.Encoding.UTF8.GetString(masked.Body);
        Assert.Contains("jkp:tomb:s:password", text);
        Assert.DoesNotContain("Gizli123", text);
        Assert.Contains("\"token\":\"live-token\"", text);
        Assert.Equal(["$.token"], masked.LiveJsonPaths); // password never appears in the declaration
    }

    [Theory]
    [InlineData("session")]
    [InlineData("cookie")]
    [InlineData("csrf")]
    [InlineData("cursor")]
    [InlineData("authToken")]
    [InlineData("sessionToken")]
    [InlineData("csrfToken")]
    [InlineData("nextCursor")]
    public void MaskReplayResponseBody_RunCredentialAllowlistFieldNames_PassThroughLive(string fieldName)
    {
        var anonymizer = new Anonymizer(Key, Options, []);
        var body = System.Text.Encoding.UTF8.GetBytes($$"""{"{{fieldName}}":"live-opaque-value-xyz"}""");

        var masked = anonymizer.MaskReplayResponseBody(body, "application/json");

        Assert.NotNull(masked);
        var text = System.Text.Encoding.UTF8.GetString(masked.Body);
        Assert.Contains("live-opaque-value-xyz", text);
        Assert.Equal([$"$.{fieldName}"], masked.LiveJsonPaths);
    }

    [Fact]
    public void MaskReplayResponseBody_FieldNameEndingInTokenizer_DoesNotMatchRunCredential_WholeWordOnly()
    {
        // "tokenizer" is one lowercase word ("tokenizer") from SplitWords' perspective, not the trailing word
        // "token" — proves the allowlist match is whole-word, never substring/prefix.
        var anonymizer = new Anonymizer(Key, Options, []);
        var body = System.Text.Encoding.UTF8.GetBytes("""{"tokenizer":"Some Free Text Value"}""");

        var masked = anonymizer.MaskReplayResponseBody(body, "application/json");

        Assert.NotNull(masked);
        Assert.Empty(masked.LiveJsonPaths);
    }

    [Fact]
    public void MaskReplayResponseBody_FieldPolicyOverride_VetoesRunCredentialPassthrough_TokenStaysMasked()
    {
        var options = new AnonymizationOptions
        {
            KeyVersion = Options.KeyVersion,
            Scope = Options.Scope,
            FieldPolicy = new Dictionary<string, FieldClass>(StringComparer.OrdinalIgnoreCase) { ["token"] = FieldClass.SecretTombstone },
        };
        var anonymizer = new Anonymizer(Key, options, []);
        var body = System.Text.Encoding.UTF8.GetBytes("""{"token":"live-token-abc123"}""");

        var masked = anonymizer.MaskReplayResponseBody(body, "application/json");

        Assert.NotNull(masked);
        var text = System.Text.Encoding.UTF8.GetString(masked.Body);
        Assert.Contains("jkp:tomb:s:token", text);
        Assert.DoesNotContain("live-token-abc123", text);
        Assert.Empty(masked.LiveJsonPaths);
    }

    [Fact]
    public void MaskReplayResponseBody_NumericCursorField_PassesThroughLive_StaysJsonNumber_NotJsonString()
    {
        var anonymizer = new Anonymizer(Key, Options, []);
        var body = System.Text.Encoding.UTF8.GetBytes("""{"cursor":42}""");

        var masked = anonymizer.MaskReplayResponseBody(body, "application/json");

        Assert.NotNull(masked);
        using var document = System.Text.Json.JsonDocument.Parse(masked.Body);
        var cursor = document.RootElement.GetProperty("cursor");
        Assert.Equal(System.Text.Json.JsonValueKind.Number, cursor.ValueKind);
        Assert.Equal(42, cursor.GetInt32());
        Assert.Equal(["$.cursor"], masked.LiveJsonPaths);
    }

    [Fact]
    public void MaskReplayResponseBody_TokenFieldInsideArray_DeclaresSingleWildcardPath_NotOnePerIndex()
    {
        var anonymizer = new Anonymizer(Key, Options, []);
        var body = System.Text.Encoding.UTF8.GetBytes(
            """{"items":[{"cursor":"c1"},{"cursor":"c2"},{"cursor":"c3"}]}""");

        var masked = anonymizer.MaskReplayResponseBody(body, "application/json");

        Assert.NotNull(masked);
        var text = System.Text.Encoding.UTF8.GetString(masked.Body);
        Assert.Contains("\"c1\"", text);
        Assert.Contains("\"c2\"", text);
        Assert.Contains("\"c3\"", text);
        Assert.Equal(["$.items[*].cursor"], masked.LiveJsonPaths);
    }

    [Fact]
    public void MaskReplayResponseBody_TokenFieldWithSpecialCharacter_PercentEncodesJsonPathSegment()
    {
        var anonymizer = new Anonymizer(Key, Options, []);
        // A JSON property name literally containing '.' — the RunCredential name match still applies (SplitWords
        // treats '.' as a separator, same as camelCase splitting), but the JSONPath segment must be encoded so
        // the declared path stays unambiguous against the '.' property-access delimiter.
        var body = """{"auth.token":"live-value"}"""u8.ToArray();

        var masked = anonymizer.MaskReplayResponseBody(body, "application/json");

        Assert.NotNull(masked);
        Assert.Equal(["$.auth%2Etoken"], masked.LiveJsonPaths);
    }

    [Fact]
    public void Anonymize_TokenFieldInBody_CapturePath_StillTombstoned_RunCredentialNeverAppliesToCapture()
    {
        // INVARIANT: RunCredential is a replay-only mechanism. The exact same field name, run through the
        // ordinary capture-side Anonymize(), must tombstone exactly as it always has.
        var anonymizer = new Anonymizer(Key, Options, []);
        var interaction = BuildInteraction(requestBodyJson: """{"token":"real-login-token"}""");

        var result = anonymizer.Anonymize(interaction);

        Assert.Contains("jkp:tomb:s:token", result.Request.Body!.Text);
        Assert.DoesNotContain("real-login-token", result.Request.Body.Text);
    }

    // ---- v1.2.0 idempotent replay masking (WHY #2) -------------------------------------------------------------
    // A synthetic value the Runner sent, echoed back by the target, used to be re-synthesized into a SECOND,
    // different value — breaking every echo-equality assertion structurally, even though nothing changed.

    [Fact]
    public void MaskReplayResponseBody_AlreadySyntheticEmailFormat_PassesThroughUnchanged()
    {
        var anonymizer = new Anonymizer(Key, Options, []);
        // Exact deterministic shape GenerateEmail produces (user-<8 lowercase hex>@example.com) — does not need
        // to correspond to any real HMAC seed; idempotency recognition is format-based, not value-based.
        var body = """{"email":"user-deadbeef@example.com"}"""u8.ToArray();

        var masked = anonymizer.MaskReplayResponseBody(body, "application/json");

        Assert.NotNull(masked);
        var text = System.Text.Encoding.UTF8.GetString(masked.Body);
        Assert.Contains("\"email\":\"user-deadbeef@example.com\"", text);
    }

    [Fact]
    public void MaskReplayResponseBody_RealLookingEmail_StillGetsMasked_NotIncorrectlyRecognizedAsSynthetic()
    {
        // Regression guard for the false-passthrough risk: an ordinary real email must NOT match the narrow
        // synthetic-email shape and must still be synthesized as before.
        var anonymizer = new Anonymizer(Key, Options, []);
        var body = """{"email":"jane.doe@realcustomer.example"}"""u8.ToArray();

        var masked = anonymizer.MaskReplayResponseBody(body, "application/json");

        Assert.NotNull(masked);
        var text = System.Text.Encoding.UTF8.GetString(masked.Body);
        Assert.DoesNotContain("jane.doe@realcustomer.example", text);
        Assert.Contains("@example.com", text); // synthesized to the configured synthetic domain
    }

    [Fact]
    public void MaskReplayResponseBody_AlreadyFingerprintEnvelope_PassesThroughUnchanged_EvenUnderDifferentFieldName()
    {
        // Simulates a request's `fp:` envelope (built from a masked corpus) being echoed back by the target
        // under a DIFFERENT response field name — value-shape recognition must catch this regardless of name.
        var anonymizer = new Anonymizer(Key, Options, []);
        var digest = FingerprintGenerator.ComputeCorrelationDigest(
            Key, Options.Scope.TenantId, Options.Scope.ProjectId, Options.Scope.Environment, "id", "original-raw-value");
        var envelope = ValueEnvelopeWriter.WriteFingerprint("s", "id", Options.KeyVersion, digest);
        var body = System.Text.Encoding.UTF8.GetBytes($$"""{"unrelatedFieldName":"{{envelope}}"}""");

        var masked = anonymizer.MaskReplayResponseBody(body, "application/json");

        Assert.NotNull(masked);
        var text = System.Text.Encoding.UTF8.GetString(masked.Body);
        Assert.Contains(envelope, text);
        Assert.Empty(masked.LiveJsonPaths); // envelope idempotency is not a RunCredential passthrough
    }

    [Fact]
    public void MaskReplayResponseBody_AlreadyTombstoneEnvelope_PassesThroughUnchanged_EvenUnderDifferentFieldName()
    {
        var anonymizer = new Anonymizer(Key, Options, []);
        var body = """{"unrelatedFieldName":"jkp:tomb:s:originalfield"}"""u8.ToArray();

        var masked = anonymizer.MaskReplayResponseBody(body, "application/json");

        Assert.NotNull(masked);
        var text = System.Text.Encoding.UTF8.GetString(masked.Body);
        Assert.Contains("jkp:tomb:s:originalfield", text);
    }

    // ---- v1.2.0 RunCredential for response headers -------------------------------------------------------------

    [Fact]
    public void ClassifyReplayResponseHeader_SetCookie_DefaultsToLivePassthrough()
    {
        var anonymizer = new Anonymizer(Key, Options, []);

        var decision = anonymizer.ClassifyReplayResponseHeader("Set-Cookie", "sessionId=abc123; Path=/; HttpOnly");

        Assert.True(decision.PassedLive);
        Assert.Equal("sessionId=abc123; Path=/; HttpOnly", decision.Value);
    }

    [Fact]
    public void ClassifyReplayResponseHeader_FieldPolicyOverride_VetoesLivePassthrough()
    {
        var options = new AnonymizationOptions
        {
            KeyVersion = Options.KeyVersion,
            Scope = Options.Scope,
            FieldPolicy = new Dictionary<string, FieldClass>(StringComparer.OrdinalIgnoreCase) { ["Set-Cookie"] = FieldClass.SecretTombstone },
        };
        var anonymizer = new Anonymizer(Key, options, []);

        var decision = anonymizer.ClassifyReplayResponseHeader("Set-Cookie", "sessionId=abc123");

        Assert.False(decision.PassedLive);
        Assert.Contains("jkp:tomb:", decision.Value);
        Assert.DoesNotContain("abc123", decision.Value);
    }

    // ---- GIZLILIK-1/G1: Identity/Correlation/AuthBinding coverage -------------------------------------------
    // Anonymize() used to return Identity/Correlation/Auth completely untouched — the JWT `sub`, user name, and
    // every claim went to the collector in PLAINTEXT even with a key configured. This closes that gap per the
    // field-by-field decision table (see task report).

    private static CapturedInteraction BuildInteractionWithSubjectCopies(string subjectId) =>
        BuildInteraction(
            identity: new IdentityInfo { IsAuthenticated = true, SubjectId = subjectId },
            correlation: new CorrelationSignals { ObservedAt = DateTimeOffset.UtcNow, SubjectId = subjectId },
            auth: new AuthBinding { AuthBearing = true, SubjectId = subjectId });

    [Fact]
    public void Anonymize_SubjectId_SameRawValue_IdentityCorrelationAndAuthBinding_ProduceIdenticalDigest()
    {
        const string subjectId = "auth0|64f1e2c3-real-user-guid";
        var anonymizer = new Anonymizer(Key, Options, []);

        var result = anonymizer.Anonymize(BuildInteractionWithSubjectCopies(subjectId));

        Assert.DoesNotContain(subjectId, result.Identity!.SubjectId);
        Assert.DoesNotContain(subjectId, result.Correlation.SubjectId);
        Assert.DoesNotContain(subjectId, result.Auth!.SubjectId);
        Assert.Equal(result.Identity.SubjectId, result.Correlation.SubjectId);
        Assert.Equal(result.Identity.SubjectId, result.Auth.SubjectId);
        Assert.StartsWith("fp:u:subject:", result.Identity.SubjectId);
    }

    [Theory]
    [InlineData("role")]
    [InlineData("http://schemas.microsoft.com/ws/2008/06/identity/claims/role")]
    public void Anonymize_RoleClaim_BothTypeSpellings_PassThroughUnchanged(string roleClaimType)
    {
        var anonymizer = new Anonymizer(Key, Options, []);
        var interaction = BuildInteraction(identity: new IdentityInfo
        {
            IsAuthenticated = true,
            Claims = new Dictionary<string, string> { [roleClaimType] = "admin" },
        });

        var result = anonymizer.Anonymize(interaction);

        Assert.Equal("admin", result.Identity!.Claims[roleClaimType]);
    }

    [Fact]
    public void Anonymize_UnrecognizedClaimType_IsFingerprinted_FailClosed()
    {
        var anonymizer = new Anonymizer(Key, Options, []);
        var interaction = BuildInteraction(identity: new IdentityInfo
        {
            IsAuthenticated = true,
            Claims = new Dictionary<string, string> { ["department"] = "engineering" },
        });

        var result = anonymizer.Anonymize(interaction);

        var transformed = result.Identity!.Claims["department"];
        Assert.NotEqual("engineering", transformed);
        Assert.StartsWith("fp:u:claim:", transformed);
    }

    [Fact]
    public void Anonymize_LowCardinalityIdentityAndCorrelationFields_PassThroughUnchanged()
    {
        var observedAt = DateTimeOffset.UtcNow;
        var anonymizer = new Anonymizer(Key, Options, []);
        var interaction = BuildInteraction(
            identity: new IdentityInfo { IsAuthenticated = true, AuthenticationScheme = "Bearer" },
            correlation: new CorrelationSignals
            {
                ObservedAt = observedAt,
                TraceId = "trace-abc",
                SpanId = "span-1",
                ParentSpanId = "span-0",
            },
            auth: new AuthBinding
            {
                AuthBearing = true,
                Scheme = "Bearer",
                SourceInteractionId = Guid.Parse("11111111-1111-1111-1111-111111111111"),
                SourceFieldPath = "$.token",
            });

        var result = anonymizer.Anonymize(interaction);

        Assert.True(result.Identity!.IsAuthenticated);
        Assert.Equal("Bearer", result.Identity.AuthenticationScheme);
        Assert.Equal("trace-abc", result.Correlation.TraceId);
        Assert.Equal("span-1", result.Correlation.SpanId);
        Assert.Equal("span-0", result.Correlation.ParentSpanId);
        Assert.Equal(observedAt, result.Correlation.ObservedAt);
        Assert.True(result.Auth!.AuthBearing);
        Assert.Equal("Bearer", result.Auth.Scheme);
        Assert.Equal(Guid.Parse("11111111-1111-1111-1111-111111111111"), result.Auth.SourceInteractionId);
        Assert.Equal("$.token", result.Auth.SourceFieldPath);
    }

    [Fact]
    public void Anonymize_NoKeyConfigured_IdentityCorrelationAndAuthBinding_PassThroughUnchanged()
    {
        const string subjectId = "real-subject-id";
        var anonymizer = new Anonymizer(key: null, Options, []);
        var interaction = BuildInteractionWithSubjectCopies(subjectId);

        var result = anonymizer.Anonymize(interaction);

        Assert.Same(interaction, result);
        Assert.Equal(subjectId, result.Identity!.SubjectId);
        Assert.Equal(subjectId, result.Correlation.SubjectId);
        Assert.Equal(subjectId, result.Auth!.SubjectId);
    }

    [Fact]
    public void Anonymize_SubjectIdAndClaims_AreDeterministic_SameInputSameOutput()
    {
        const string subjectId = "deterministic-subject";
        var anonymizer = new Anonymizer(Key, Options, []);
        Func<CapturedInteraction> build = () => BuildInteraction(identity: new IdentityInfo
        {
            IsAuthenticated = true,
            SubjectId = subjectId,
            UserName = "ayse.yilmaz",
            Claims = new Dictionary<string, string> { ["department"] = "engineering", ["role"] = "admin" },
        });

        var first = anonymizer.Anonymize(build());
        var second = anonymizer.Anonymize(build());

        Assert.Equal(first.Identity!.SubjectId, second.Identity!.SubjectId);
        Assert.Equal(first.Identity.UserName, second.Identity.UserName);
        Assert.Equal(first.Identity.Claims["department"], second.Identity.Claims["department"]);
        Assert.Equal(first.Identity.Claims["role"], second.Identity.Claims["role"]);
    }

    [Fact]
    public void Anonymize_SetsAnonScheme_HmacSha256V2()
    {
        var anonymizer = new Anonymizer(Key, Options, []);

        var result = anonymizer.Anonymize(BuildInteraction());

        Assert.Equal("hmac-sha256-v2", result.Anon!.Scheme);
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
