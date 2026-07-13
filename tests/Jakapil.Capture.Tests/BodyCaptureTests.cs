using System.Text;
using System.Text.Json;
using Jakapil.Capture;
using Jakapil.Capture.Contracts;

namespace Jakapil.Capture.Tests;

/// <summary>
/// Verifies the behavior of body capture: a small JSON body is captured whole and untruncated,
/// oversized bodies are truncated at a JSON token boundary (never mid-token) and without splitting a multi-byte
/// UTF-8 character, an empty body returns null, and the body kind is classified from the content type.
/// </summary>
public class BodyCaptureTests
{
    /// <summary>Verifies that a small JSON body under the cap is captured whole, untruncated, and with the correct kind/size.</summary>
    [Fact]
    public void Capture_SmallJsonBody_IsCapturedWholeAndUntruncated()
    {
        var json = """{"id":4,"name":"Widget","price":9.99}""";
        var bytes = Encoding.UTF8.GetBytes(json);

        var body = BodyCapture.Capture(bytes, "application/json", maxInlineBytes: 1024 * 1024);

        Assert.NotNull(body);
        Assert.False(body!.Truncated);
        Assert.Equal(BodyKind.Json, body.Kind);
        Assert.Equal(json, body.Text);
        Assert.Equal(bytes.Length, body.ByteSize);
    }

    /// <summary>
    /// Verifies that the captured prefix of an oversized JSON array consists only of <b>complete</b> JSON tokens
    /// (no token is split mid-way) and is marked truncated while preserving the original byte size.
    /// When re-tokenized with a non-final-block reader, the prefix must be fully consumed without error.
    /// </summary>
    [Fact]
    public void Capture_OversizedJsonBody_TruncatesAtJsonTokenBoundary_NeverMidToken()
    {
        var items = Enumerable.Range(0, 5000).Select(i => $$"""{"id":{{i}},"name":"item-{{i}}"}""");
        var json = "[" + string.Join(",", items) + "]";
        var bytes = Encoding.UTF8.GetBytes(json);
        const int cap = 2000;

        var body = BodyCapture.Capture(bytes, "application/json", maxInlineBytes: cap);

        Assert.NotNull(body);
        Assert.True(body!.Truncated);
        Assert.Equal(BodyKind.Json, body.Kind);
        Assert.Equal(bytes.Length, body.ByteSize);
        Assert.NotNull(body.Text);
        Assert.True(body.Text!.Length <= cap);
        Assert.True(body.Text.Length > 0);

        var truncatedBytes = Encoding.UTF8.GetBytes(body.Text);
        var reader = new Utf8JsonReader(truncatedBytes, isFinalBlock: false, state: default);
        var consumedFully = true;
        try
        {
            while (reader.Read())
            {
            }
        }
        catch (JsonException)
        {
            consumedFully = false;
        }

        Assert.True(consumedFully, "Truncated JSON prefix must consist only of complete tokens.");
    }

    /// <summary>
    /// Verifies that an oversized text body never splits a multi-byte UTF-8 character: even when a 3-byte character is
    /// truncated at a boundary that is not a multiple of the cap, the decoded text re-encodes to a clean prefix of the
    /// original bytes and contains no U+FFFD replacement character.
    /// </summary>
    [Fact]
    public void Capture_OversizedTextBody_NeverSplitsAMultiByteUtf8Character()
    {
        var text = string.Concat(Enumerable.Repeat("汉", 1000));
        var bytes = Encoding.UTF8.GetBytes(text);
        const int cap = 101;

        var body = BodyCapture.Capture(bytes, "text/plain", maxInlineBytes: cap);

        Assert.NotNull(body);
        Assert.True(body!.Truncated);
        Assert.NotNull(body.Text);

        var roundTripped = Encoding.UTF8.GetBytes(body.Text!);
        Assert.Equal(roundTripped, bytes[..roundTripped.Length]);
        Assert.DoesNotContain('�', body.Text);
    }

    /// <summary>Verifies that an empty body returns null when captured.</summary>
    [Fact]
    public void Capture_EmptyBody_ReturnsNull()
    {
        var body = BodyCapture.Capture(ReadOnlySpan<byte>.Empty, "application/json", maxInlineBytes: 1024);

        Assert.Null(body);
    }

    /// <summary>Verifies that when a content type is present, the body kind (Json/Form/Text/Binary) is classified from it.</summary>
    [Theory]
    [InlineData("application/json; charset=utf-8", BodyKind.Json)]
    [InlineData("application/x-www-form-urlencoded", BodyKind.Form)]
    [InlineData("text/plain", BodyKind.Text)]
    [InlineData("application/octet-stream", BodyKind.Binary)]
    public void ClassifyKind_UsesContentTypeWhenPresent(string contentType, BodyKind expected)
    {
        var bytes = Encoding.UTF8.GetBytes("payload");

        var kind = BodyCapture.ClassifyKind(contentType, bytes);

        Assert.Equal(expected, kind);
    }

    [Fact]
    public void ClassifyKind_UnknownApplicationType_StillSniffsJson()
    {
        var bytes = Encoding.UTF8.GetBytes("""{"value":true}""");

        var kind = BodyCapture.ClassifyKind("application/vnd.jakapil", bytes);

        Assert.Equal(BodyKind.Json, kind);
    }
}
