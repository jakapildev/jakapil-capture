namespace Jakapil.Capture.Replay;

/// <summary>
/// A write-only response stream used ONLY for a request whose <c>X-Jakapil-Replay</c> signature has already
/// verified: every byte the application writes is accumulated into an in-memory buffer and NOTHING is
/// forwarded to the real response stream while the request is in flight.
/// </summary>
/// <remarks>
/// This is the opposite strategy from <see cref="CapturingResponseStream"/> (which tees every write to the
/// real stream immediately, for zero-latency production capture): a replay response must be MASKED before any
/// byte reaches the caller, so the real bytes cannot be released until the complete body is known and has been
/// transformed. This is safe specifically because signed-replay traffic only ever originates from the Jakapil
/// Runner running a test scenario against a non-production target (ADR-0003 §8.5) — it is not
/// production load, so holding the full response in memory for the duration of one request is an acceptable
/// trade for the ability to rewrite it.
/// <para>
/// Bounded by <see cref="Jakapil.Capture.Replay.ReplayVerificationOptions.MaxMaskedResponseBytes"/>: once that
/// many bytes have been accumulated, further bytes are still counted (<see cref="TotalBytesWritten"/>) but are
/// no longer buffered and <see cref="Truncated"/> is set. The caller (<c>JakapilCaptureMiddleware</c>) must
/// treat a truncated buffer as unmaskable — see that type's masking-finalization logic.
/// </para>
/// </remarks>
internal sealed class ReplayMaskingResponseStream : Stream
{
    private readonly int _maxBufferedBytes;
    private readonly MemoryStream _buffer = new();

    public ReplayMaskingResponseStream(int maxBufferedBytes)
    {
        _maxBufferedBytes = maxBufferedBytes;
    }

    /// <summary>True once the application has written more than <see cref="Jakapil.Capture.Replay.ReplayVerificationOptions.MaxMaskedResponseBytes"/>
    /// — the buffer no longer holds the complete response body, so it must not be treated as maskable OR as a
    /// faithful copy of what the application produced.</summary>
    public bool Truncated { get; private set; }

    /// <summary>The total bytes the application wrote, independent of how much was actually buffered.</summary>
    public long TotalBytesWritten { get; private set; }

    /// <summary>The buffered bytes — the COMPLETE response body when <see cref="Truncated"/> is false.</summary>
    public ReadOnlyMemory<byte> BufferedBytes => _buffer.GetBuffer().AsMemory(0, (int)_buffer.Length);

    private void Accumulate(ReadOnlySpan<byte> data)
    {
        TotalBytesWritten += data.Length;
        if (Truncated)
        {
            return;
        }

        var remaining = _maxBufferedBytes - (int)_buffer.Length;
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

    public override void Write(byte[] buffer, int offset, int count) => Accumulate(buffer.AsSpan(offset, count));

    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        Accumulate(buffer.Span);
        return ValueTask.CompletedTask;
    }

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        Accumulate(buffer.AsSpan(offset, count));
        return Task.CompletedTask;
    }

    /// <summary>No-op deliberately: forwarding a flush to the real response stream would start sending headers
    /// before masking has run.</summary>
    public override void Flush()
    {
    }

    /// <summary>No-op deliberately — see <see cref="Flush"/>.</summary>
    public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    public override bool CanRead => false;

    public override bool CanSeek => false;

    public override bool CanWrite => true;

    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _buffer.Dispose();
        }

        base.Dispose(disposing);
    }
}
