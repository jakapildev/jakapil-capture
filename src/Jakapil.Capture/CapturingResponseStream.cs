using Microsoft.AspNetCore.Http;

namespace Jakapil.Capture;

/// <summary>A pass-through response stream: every byte the application writes is forwarded to the real response body immediately, while a bounded copy is set aside for capture (tee).</summary>
/// <remarks>
/// Streaming/SSE/large downloads are flushed incrementally, and the response seen by the client is never buffered,
/// modified, or delayed.
/// <para>
/// Two safeguards keep the target application safe (design principle: the target application is never broken):
/// <list type="bullet">
/// <item>The capture copy stops at <see cref="_maxCapturedBytes"/>; beyond that the body is marked
/// <see cref="Truncated"/> and no more is buffered — memory is bounded regardless of response size.</item>
/// <item>Streaming content types are captured with metadata only: no body is ever buffered
/// (<see cref="MetadataOnly"/>), so a never-ending SSE stream cannot accumulate in memory.</item>
/// </list>
/// The inner stream is written on every call before anything else, so a capture error can never affect what the
/// client receives.
/// </para>
/// </remarks>
internal sealed class CapturingResponseStream : Stream
{
    private readonly Stream _inner;
    private readonly HttpResponse _response;
    private readonly int _maxCapturedBytes;
    private readonly string[] _streamingContentTypes;
    private readonly MemoryStream _buffer = new();

    private bool _decided;
    private bool _capture;

    /// <summary>Constructs the stream from the inner real stream, the response, the capture byte limit, and the streaming content types.</summary>
    public CapturingResponseStream(Stream inner, HttpResponse response, int maxCapturedBytes, string[] streamingContentTypes)
    {
        _inner = inner;
        _response = response;
        _maxCapturedBytes = maxCapturedBytes;
        _streamingContentTypes = streamingContentTypes;
    }

    /// <summary>The captured (possibly truncated) response bytes; empty only in metadata-only mode.</summary>
    public ReadOnlySpan<byte> CapturedBytes => _buffer.GetBuffer().AsSpan(0, (int)_buffer.Length);

    /// <summary>True when the response exceeded the capture limit and the captured copy is incomplete.</summary>
    public bool Truncated { get; private set; }

    /// <summary>True when the content type is streaming and no body was buffered.</summary>
    public bool MetadataOnly { get; private set; }

    /// <summary>The total bytes the application wrote (the real response size), independent of how much was captured.</summary>
    public long TotalBytesWritten { get; private set; }

    /// <summary>On the first write, decides once — by inspecting the content type — whether this response should be
    /// captured (metadata only if streaming).</summary>
    private void EnsureDecided()
    {
        if (_decided)
        {
            return;
        }

        _decided = true;
        var contentType = _response.ContentType;
        if (!string.IsNullOrEmpty(contentType))
        {
            var mediaType = contentType.Split(';', 2)[0].Trim();
            foreach (var streaming in _streamingContentTypes)
            {
                if (mediaType.StartsWith(streaming, StringComparison.OrdinalIgnoreCase))
                {
                    MetadataOnly = true;
                    _capture = false;
                    return;
                }
            }
        }

        _capture = true;
    }

    /// <summary>Adds the written bytes to the total size and, if capture is on, copies up to the limit; if the limit is
    /// exceeded, the excess is not buffered and it is marked as truncated.</summary>
    private void Tee(ReadOnlySpan<byte> data)
    {
        TotalBytesWritten += data.Length;
        EnsureDecided();
        if (!_capture)
        {
            return;
        }

        var remaining = _maxCapturedBytes - (int)_buffer.Length;
        if (remaining <= 0)
        {
            Truncated = true;
            return;
        }

        if (data.Length > remaining)
        {
            _buffer.Write(data[..remaining]);
            Truncated = true;
        }
        else
        {
            _buffer.Write(data);
        }
    }

    /// <summary>Writes the bytes to the inner stream first, then tees them into the capture copy.</summary>
    public override void Write(byte[] buffer, int offset, int count)
    {
        _inner.Write(buffer, offset, count);
        Tee(buffer.AsSpan(offset, count));
    }

    /// <summary>Writes the bytes to the inner stream asynchronously first, then tees them into the capture copy.</summary>
    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        await _inner.WriteAsync(buffer, cancellationToken);
        Tee(buffer.Span);
    }

    /// <summary>Writes the bytes to the inner stream asynchronously first, then tees them into the capture copy.</summary>
    public override async Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        await _inner.WriteAsync(buffer.AsMemory(offset, count), cancellationToken);
        Tee(buffer.AsSpan(offset, count));
    }

    /// <summary>Flushes the inner stream.</summary>
    public override void Flush() => _inner.Flush();

    /// <summary>Flushes the inner stream asynchronously.</summary>
    public override Task FlushAsync(CancellationToken cancellationToken) => _inner.FlushAsync(cancellationToken);

    /// <summary>The stream cannot be read.</summary>
    public override bool CanRead => false;

    /// <summary>The stream cannot seek.</summary>
    public override bool CanSeek => false;

    /// <summary>The stream is writable.</summary>
    public override bool CanWrite => true;

    /// <summary>Not supported.</summary>
    public override long Length => throw new NotSupportedException();

    /// <summary>Not supported.</summary>
    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    /// <summary>Not supported; this stream is write-only.</summary>
    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    /// <summary>Not supported.</summary>
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    /// <summary>Not supported.</summary>
    public override void SetLength(long value) => throw new NotSupportedException();

    /// <summary>Releases the capture buffer.</summary>
    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _buffer.Dispose();
        }

        base.Dispose(disposing);
    }
}
