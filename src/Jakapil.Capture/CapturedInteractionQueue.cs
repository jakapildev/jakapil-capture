using System.Threading.Channels;
using Jakapil.Capture.Contracts;
using Microsoft.Extensions.Options;

namespace Jakapil.Capture;

/// <summary>
/// In-memory handoff between the capture middleware (producer, on the request thread) and the background
/// export worker (consumer).
/// </summary>
/// <remarks>
/// It is bounded so that a slow/unreachable collector cannot create unbounded memory pressure on the target
/// application; under backpressure, rather than blocking the request pipeline, the queue's oldest interaction is
/// dropped ("drop-and-count"). The export worker drains the queue via <see cref="CapturedInteractionQueue.Reader"/>.
/// </remarks>
public interface ICapturedInteractionQueue
{
    /// <summary>Writes an interaction to the queue; if the queue is full the oldest entry is dropped.</summary>
    ValueTask EnqueueAsync(CapturedInteraction interaction, CancellationToken ct = default);

    /// <summary>
    /// Discards, without sending, all unsent interactions waiting in the queue (Phase 14 M4 — called by
    /// <see cref="CaptureConfigPollWorker"/> when remote capture is turned off). Discarded items never return to
    /// the queue; this does NOT send a final time, it drops silently.
    /// </summary>
    void Clear();
}

/// <summary>An <see cref="ICapturedInteractionQueue"/> implementation built on a bounded channel; drops the
/// oldest entry when full, configured for a single reader / multiple writers.</summary>
public sealed class CapturedInteractionQueue : ICapturedInteractionQueue
{
    private readonly Channel<CapturedInteraction> _channel;
    private long _dropped;

    /// <summary>Builds the queue as a channel bounded to the configured capacity that drops the oldest entry.</summary>
    public CapturedInteractionQueue(IOptions<JakapilCaptureOptions> options)
    {
        _channel = Channel.CreateBounded<CapturedInteraction>(
            new BoundedChannelOptions(Math.Max(1, options.Value.QueueCapacity))
            {
                FullMode = BoundedChannelFullMode.DropOldest,
                SingleReader = true,
                SingleWriter = false,
            },
            itemDropped: _ => Interlocked.Increment(ref _dropped));
    }

    /// <summary>Drained by the export worker; the middleware only writes.</summary>
    internal ChannelReader<CapturedInteraction> Reader => _channel.Reader;

    /// <summary>Backpressure observability — the number of interactions dropped via DropOldest while the queue
    /// was full.</summary>
    public long DroppedCount => Interlocked.Read(ref _dropped);

    /// <summary>Writes the interaction to the bounded channel.</summary>
    public ValueTask EnqueueAsync(CapturedInteraction interaction, CancellationToken ct = default)
        => _channel.Writer.WriteAsync(interaction, ct);

    /// <inheritdoc />
    public void Clear()
    {
        while (_channel.Reader.TryRead(out _))
        {
        }
    }
}
