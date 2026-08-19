using Jakapil.Capture;
using Jakapil.Capture.Anonymization;

namespace Jakapil.Capture.Tests;

/// <summary>
/// Proves that <see cref="JakapilCaptureOptionsValidator"/> correctly distinguishes valid/invalid configuration
/// combinations (CollectorUri/IngestKey required only when Enabled=true, the ingest key's format, the
/// fail-closed anonymization requirement, positive buffer/batch fields, SampleRate range).
/// </summary>
/// <remarks>
/// <b>No test here mutates the process environment.</b> The validator reads environment variables through an
/// injected delegate, so "the anonymization key is set" and "it is unset" are expressed by
/// <see cref="ValidatorWithAnonymizationKey"/> and <see cref="Validator"/> respectively. Setting a real
/// environment variable would be a process-global mutation shared with every other xUnit test collection
/// running in parallel — inherently racy, and it would additionally make every result depend on whether the
/// developer's own machine happens to export <c>JAKAPIL_ANON_KEY</c>. The delegate removes both problems and
/// needs no cleanup.
/// </remarks>
public sealed class JakapilCaptureOptionsValidatorTests
{
    /// <summary>A well-formed ingest key: <c>jk_</c> + 16 uppercase-hex scope ref + <c>_</c> + 64 uppercase-hex secret.</summary>
    private const string WellFormedIngestKey =
        "jk_0123456789ABCDEF_0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";

    /// <summary>A validator for which NO environment variable is set.</summary>
    private static readonly JakapilCaptureOptionsValidator Validator = new(_ => null);

    /// <summary>A validator for which the default anonymization key variable IS set.</summary>
    private static readonly JakapilCaptureOptionsValidator ValidatorWithAnonymizationKey =
        new(name => name == AnonymizationOptions.DefaultKeyEnvironmentVariable ? "test-anonymization-key" : null);

    /// <summary>Builds an otherwise-valid enabled configuration; individual tests vary one field.</summary>
    private static JakapilCaptureOptions ValidEnabledOptions() => new()
    {
        Enabled = true,
        CollectorUri = "https://collector.test",
        IngestKey = WellFormedIngestKey,
    };

    /// <summary>A configuration with all fields default plus a valid CollectorUri/IngestKey should succeed
    /// when the anonymization key is present.</summary>
    [Fact]
    public void ValidConfiguration_Succeeds()
    {
        var result = ValidatorWithAnonymizationKey.Validate(null, ValidEnabledOptions());

        Assert.True(result.Succeeded);
    }

    /// <summary>When Enabled=true and CollectorUri is missing, validation should fail.</summary>
    [Fact]
    public void EnabledTrue_CollectorUriMissing_Fails()
    {
        var options = ValidEnabledOptions();
        options.CollectorUri = null;

        var result = ValidatorWithAnonymizationKey.Validate(null, options);

        Assert.True(result.Failed);
    }

    /// <summary>When Enabled=true and IngestKey is missing, validation should fail.</summary>
    [Fact]
    public void EnabledTrue_IngestKeyMissing_Fails()
    {
        var options = ValidEnabledOptions();
        options.IngestKey = null;

        var result = ValidatorWithAnonymizationKey.Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains(result.Failures!, f => f.Contains("cannot be empty", StringComparison.Ordinal));
    }

    /// <summary>When Enabled=true and CollectorUri is a relative (non-absolute) URI, validation should fail.</summary>
    [Fact]
    public void EnabledTrue_CollectorUriNotAbsolute_Fails()
    {
        var options = ValidEnabledOptions();
        options.CollectorUri = "not-a-uri";

        var result = ValidatorWithAnonymizationKey.Validate(null, options);

        Assert.True(result.Failed);
    }

    /// <summary>When Enabled=false, validation should succeed even if CollectorUri/IngestKey are missing (a
    /// disabled SDK does not bring down the host) — and the anonymization requirement does not apply either,
    /// because a disabled SDK captures nothing at all.</summary>
    [Fact]
    public void EnabledFalse_SucceedsEvenIfCollectorUriAndIngestKeyMissing()
    {
        var options = new JakapilCaptureOptions
        {
            Enabled = false,
            CollectorUri = null,
            IngestKey = null,
        };

        var result = Validator.Validate(null, options);

        Assert.True(result.Succeeded);
    }

    /// <summary>A negative QueueCapacity should make validation fail.</summary>
    [Fact]
    public void NegativeQueueCapacity_Fails()
    {
        var options = new JakapilCaptureOptions
        {
            Enabled = false,
            QueueCapacity = -1,
        };

        var result = Validator.Validate(null, options);

        Assert.True(result.Failed);
    }

    /// <summary>When SampleRate is outside the [0,1] range (e.g. 1.5), validation should fail.</summary>
    [Theory]
    [InlineData(-0.1)]
    [InlineData(1.1)]
    public void SampleRateOutsideRange_Fails(double sampleRate)
    {
        var options = new JakapilCaptureOptions
        {
            Enabled = false,
            SampleRate = sampleRate,
        };

        var result = Validator.Validate(null, options);

        Assert.True(result.Failed);
    }

    /// <summary>SampleRate should be valid at the endpoints of the range (0 and 1).</summary>
    [Theory]
    [InlineData(0.0)]
    [InlineData(1.0)]
    public void SampleRateAtRangeEndpoints_Succeeds(double sampleRate)
    {
        var options = new JakapilCaptureOptions
        {
            Enabled = false,
            SampleRate = sampleRate,
        };

        var result = Validator.Validate(null, options);

        Assert.True(result.Succeeded);
    }

    /// <summary>When one of the fields that must be positive (e.g. ExportBatchMaxItems) is zero or negative, it should fail.</summary>
    [Theory]
    [InlineData(0)]
    [InlineData(-5)]
    public void ZeroOrNegativeExportBatchMaxItems_Fails(int value)
    {
        var options = new JakapilCaptureOptions
        {
            Enabled = false,
            ExportBatchMaxItems = value,
        };

        var result = Validator.Validate(null, options);

        Assert.True(result.Failed);
    }

    /// <summary>The fail-closed default: with capture enabled and no anonymization key in the environment,
    /// startup must fail rather than quietly shipping plaintext production data.</summary>
    [Fact]
    public void RequireAnonymizationDefault_KeyEnvironmentVariableUnset_Fails()
    {
        var options = ValidEnabledOptions();

        Assert.True(options.Anonymization.RequireAnonymization);

        var result = Validator.Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains(result.Failures!, f =>
            f.Contains(AnonymizationOptions.DefaultKeyEnvironmentVariable, StringComparison.Ordinal)
            && f.Contains("PLAINTEXT", StringComparison.Ordinal)
            && f.Contains("Anonymization.RequireAnonymization = false", StringComparison.Ordinal));
    }

    /// <summary>The requirement is satisfied as soon as the configured variable holds a value.</summary>
    [Fact]
    public void RequireAnonymizationTrue_KeyEnvironmentVariableSet_Succeeds()
    {
        var result = ValidatorWithAnonymizationKey.Validate(null, ValidEnabledOptions());

        Assert.True(result.Succeeded);
    }

    /// <summary>A whitespace-only value is treated as unset — it would produce an unusable key.</summary>
    [Fact]
    public void RequireAnonymizationTrue_KeyEnvironmentVariableWhitespace_Fails()
    {
        var validator = new JakapilCaptureOptionsValidator(_ => "   ");

        var result = validator.Validate(null, ValidEnabledOptions());

        Assert.True(result.Failed);
    }

    /// <summary>The variable name is configurable, so the requirement must follow it rather than the default.</summary>
    [Fact]
    public void RequireAnonymizationTrue_CustomKeyEnvironmentVariableSet_Succeeds()
    {
        var options = ValidEnabledOptions();
        options.Anonymization.KeyEnvironmentVariable = "CUSTOM_ANON_KEY";
        var validator = new JakapilCaptureOptionsValidator(name => name == "CUSTOM_ANON_KEY" ? "value" : null);

        var result = validator.Validate(null, options);

        Assert.True(result.Succeeded);
    }

    /// <summary>The explicit opt-out keeps today's pass-through behaviour available for deliberate use.</summary>
    [Fact]
    public void RequireAnonymizationFalse_KeyEnvironmentVariableUnset_Succeeds()
    {
        var options = ValidEnabledOptions();
        options.Anonymization.RequireAnonymization = false;

        var result = Validator.Validate(null, options);

        Assert.True(result.Succeeded);
    }

    /// <summary>Every way an ingest key can deviate from <c>jk_&lt;16 hex&gt;_&lt;64 hex&gt;</c> must be rejected
    /// at startup: a key that cannot be parsed carries no scope reference, so the SDK could not derive its
    /// anonymization domain from it and the collector would reject it anyway.</summary>
    [Theory]
    // No jk_ prefix (the legacy key format).
    [InlineData("ik_test")]
    // Right shape, wrong prefix.
    [InlineData("xx_0123456789ABCDEF_0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")]
    // Prefix case matters — matching is ordinal.
    [InlineData("JK_0123456789ABCDEF_0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")]
    // Scope ref one character short.
    [InlineData("jk_0123456789ABCDE_0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")]
    // Scope ref one character long.
    [InlineData("jk_0123456789ABCDEF0_0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")]
    // Lowercase hex in the scope ref.
    [InlineData("jk_0123456789abcdef_0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")]
    // Lowercase hex in the secret.
    [InlineData("jk_0123456789ABCDEF_0123456789abcdef0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")]
    // Non-hex letter in the scope ref.
    [InlineData("jk_0123456789ABCDEG_0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")]
    // A second separator hidden inside the secret (total length still correct).
    [InlineData("jk_0123456789ABCDEF_0123456789ABCDE_0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")]
    // Secret one character short.
    [InlineData("jk_0123456789ABCDEF_0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDE")]
    // Secret one character long.
    [InlineData("jk_0123456789ABCDEF_0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEFA")]
    // Prefix only.
    [InlineData("jk_")]
    public void EnabledTrue_MalformedIngestKey_Fails(string ingestKey)
    {
        var options = ValidEnabledOptions();
        options.IngestKey = ingestKey;

        var result = ValidatorWithAnonymizationKey.Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains(result.Failures!, f => f.Contains("malformed", StringComparison.Ordinal));
    }

    /// <summary>A well-formed key passes and does not produce a format failure.</summary>
    [Fact]
    public void EnabledTrue_WellFormedIngestKey_Succeeds()
    {
        var result = ValidatorWithAnonymizationKey.Validate(null, ValidEnabledOptions());

        Assert.True(result.Succeeded);
    }

    /// <summary>The key format is only enforced for an enabled SDK — a disabled one never sends anything, so a
    /// leftover legacy key in configuration must not block host startup.</summary>
    [Fact]
    public void EnabledFalse_MalformedIngestKey_Succeeds()
    {
        var options = new JakapilCaptureOptions
        {
            Enabled = false,
            CollectorUri = "https://collector.test",
            IngestKey = "ik_test",
        };

        var result = Validator.Validate(null, options);

        Assert.True(result.Succeeded);
    }
}
