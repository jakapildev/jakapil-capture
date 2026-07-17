using Jakapil.Capture;

namespace Jakapil.Capture.Tests;

/// <summary>
/// Proves that <see cref="JakapilCaptureOptionsValidator"/> correctly distinguishes valid/invalid configuration
/// combinations (CollectorUri/IngestKey required only when Enabled=true, positive buffer/batch fields, SampleRate
/// range).
/// </summary>
public sealed class JakapilCaptureOptionsValidatorTests
{
    private static readonly JakapilCaptureOptionsValidator Validator = new();

    /// <summary>A configuration with all fields default plus a valid CollectorUri/IngestKey should succeed.</summary>
    [Fact]
    public void ValidConfiguration_Succeeds()
    {
        var options = new JakapilCaptureOptions
        {
            CollectorUri = "https://collector.test",
            IngestKey = "ik_test",
        };

        var result = Validator.Validate(null, options);

        Assert.True(result.Succeeded);
    }

    /// <summary>When Enabled=true and CollectorUri is missing, validation should fail.</summary>
    [Fact]
    public void EnabledTrue_CollectorUriMissing_Fails()
    {
        var options = new JakapilCaptureOptions
        {
            Enabled = true,
            CollectorUri = null,
            IngestKey = "ik_test",
        };

        var result = Validator.Validate(null, options);

        Assert.True(result.Failed);
    }

    /// <summary>When Enabled=true and IngestKey is missing, validation should fail.</summary>
    [Fact]
    public void EnabledTrue_IngestKeyMissing_Fails()
    {
        var options = new JakapilCaptureOptions
        {
            Enabled = true,
            CollectorUri = "https://collector.test",
            IngestKey = null,
        };

        var result = Validator.Validate(null, options);

        Assert.True(result.Failed);
    }

    /// <summary>When Enabled=true and CollectorUri is a relative (non-absolute) URI, validation should fail.</summary>
    [Fact]
    public void EnabledTrue_CollectorUriNotAbsolute_Fails()
    {
        var options = new JakapilCaptureOptions
        {
            Enabled = true,
            CollectorUri = "not-a-uri",
            IngestKey = "ik_test",
        };

        var result = Validator.Validate(null, options);

        Assert.True(result.Failed);
    }

    /// <summary>When Enabled=false, validation should succeed even if CollectorUri/IngestKey are missing (a disabled SDK does not bring down the host).</summary>
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
}
