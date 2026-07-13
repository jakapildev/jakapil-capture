using System.Text;
using System.Text.Json;
using Jakapil.Capture.Contracts;

namespace Jakapil.Capture;

/// <summary>
/// Converts raw request/response bytes into a <see cref="CapturedBody"/>.
/// </summary>
/// <remarks>
/// Bodies below the inline limit are captured whole; bodies above the limit are truncated, but never in the
/// middle of a character or token — for JSON bodies the cut is made at the last complete token before the limit,
/// and for everything else at the last complete UTF-8 code point. Any case that exceeds the size/is truncated is
/// always flagged with <see cref="CapturedBody.Truncated"/>; there is no silent corruption.
/// </remarks>
public static class BodyCapture
{
    /// <summary>Classifies the raw bytes by content type and produces a <see cref="CapturedBody"/>;
    /// returns null for an empty body.</summary>
    /// <remarks>Truncates bodies that exceed the limit at a safe boundary and flags them as truncated.</remarks>
    public static CapturedBody? Capture(ReadOnlySpan<byte> bytes, string? contentType, int maxInlineBytes)
    {
        if (bytes.Length == 0)
        {
            return null;
        }

        var kind = ClassifyKind(contentType, bytes);

        if (bytes.Length <= maxInlineBytes)
        {
            return new CapturedBody
            {
                Text = DecodeText(bytes, kind),
                ByteSize = bytes.Length,
                Truncated = false,
                Kind = kind,
            };
        }

        var safeLength = kind == BodyKind.Json
            ? FindJsonSafeBoundary(bytes, maxInlineBytes)
            : FindUtf8SafeBoundary(bytes, maxInlineBytes);

        return new CapturedBody
        {
            Text = DecodeText(bytes[..safeLength], kind),
            ByteSize = bytes.Length,
            Truncated = true,
            Kind = kind,
        };
    }

    /// <summary>Determines a body's <see cref="BodyKind"/> from its content type and, if needed, by inspecting
    /// the start of the bytes.</summary>
    /// <remarks>If there is no content type or it is an unknown <c>application/*</c> type, a best-effort check
    /// looks for a JSON document (<c>{</c> or <c>[</c>) at the start of the bytes; otherwise it is treated as
    /// binary.</remarks>
    public static BodyKind ClassifyKind(string? contentType, ReadOnlySpan<byte> bytes)
    {
        if (!string.IsNullOrEmpty(contentType))
        {
            var mediaType = contentType.Split(';', 2)[0].Trim();
            if (mediaType.Contains("json", StringComparison.OrdinalIgnoreCase))
            {
                return BodyKind.Json;
            }
            if (mediaType.Equals("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase)
                || mediaType.Equals("multipart/form-data", StringComparison.OrdinalIgnoreCase))
            {
                return BodyKind.Form;
            }
            if (mediaType.StartsWith("text/", StringComparison.OrdinalIgnoreCase)
                || mediaType.Equals("application/xml", StringComparison.OrdinalIgnoreCase))
            {
                return BodyKind.Text;
            }
            if (!mediaType.StartsWith("application/", StringComparison.OrdinalIgnoreCase)
                && !mediaType.Contains('+'))
            {
                return BodyKind.Binary;
            }
        }

        var trimmed = bytes;
        var i = 0;
        while (i < trimmed.Length && IsJsonWhitespace(trimmed[i])) i++;
        if (i < trimmed.Length && (trimmed[i] == (byte)'{' || trimmed[i] == (byte)'['))
        {
            return BodyKind.Json;
        }

        return BodyKind.Binary;
    }

    /// <summary>Reports whether a byte is a JSON whitespace character (space, tab, CR, LF).</summary>
    private static bool IsJsonWhitespace(byte b) => b is (byte)' ' or (byte)'\t' or (byte)'\r' or (byte)'\n';

    /// <summary>Decodes textual bodies as UTF-8.</summary>
    /// <remarks>Binary bodies are not inlined as text; only their size/kind is recorded and null is returned.</remarks>
    private static string? DecodeText(ReadOnlySpan<byte> bytes, BodyKind kind)
    {
        if (kind == BodyKind.Binary)
        {
            return null;
        }

        return Encoding.UTF8.GetString(bytes);
    }

    /// <summary>
    /// Finds the byte offset of the last complete JSON token at or before position <paramref name="cap"/>.
    /// </summary>
    /// <remarks>
    /// <see cref="Utf8JsonReader"/> is used in non-final-block mode, so a token that crosses the limit does not
    /// throw an exception but is reported as "more data needed". If the token at the boundary is corrupt/incomplete
    /// the exception is swallowed and the end of the last well-formed token before it is returned.
    /// </remarks>
    internal static int FindJsonSafeBoundary(ReadOnlySpan<byte> bytes, int cap)
    {
        var window = bytes[..Math.Min(cap, bytes.Length)];
        var reader = new Utf8JsonReader(window, isFinalBlock: false, state: default);
        long lastGoodPosition = 0;
        try
        {
            while (reader.Read())
            {
                lastGoodPosition = reader.BytesConsumed;
            }
        }
        catch (JsonException)
        {
        }

        return (int)lastGoodPosition;
    }

    /// <summary>
    /// Backs off from a half-finished UTF-8 multi-byte sequence at the boundary, so decoding never splits a
    /// character.
    /// </summary>
    /// <remarks>
    /// Walks back over the continuation bytes (<c>10xxxxxx</c>) to the lead byte of the last sequence; if the
    /// sequence fits exactly within the limit the limit is returned, otherwise the start of the sequence is returned.
    /// </remarks>
    internal static int FindUtf8SafeBoundary(ReadOnlySpan<byte> bytes, int cap)
    {
        var len = Math.Min(cap, bytes.Length);
        if (len == 0)
        {
            return 0;
        }

        var seqStart = len - 1;
        while (seqStart > 0 && (bytes[seqStart] & 0xC0) == 0x80)
        {
            seqStart--;
        }

        var leadByte = bytes[seqStart];
        if (leadByte < 0x80)
        {
            return len;
        }

        var expectedLength = leadByte switch
        {
            >= 0xF0 => 4,
            >= 0xE0 => 3,
            >= 0xC0 => 2,
            _ => 1,
        };

        return seqStart + expectedLength <= len ? len : seqStart;
    }
}
