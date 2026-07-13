using Jakapil.Capture;
using Jakapil.Capture.Contracts;
using Microsoft.Extensions.Options;

namespace Jakapil.Capture.Tests;

/// <summary>
/// Verifies <see cref="CapturedInteractionQueue"/>'s bounded-capacity/drop-oldest (DropOldest) behavior and the
/// <see cref="CapturedInteractionQueue.Clear"/> behavior added in Phase 14 M4 (dropping the queue without draining
/// it when capture is remotely turned off).
/// </summary>
public sealed class CapturedInteractionQueueTests
{
    private static CapturedInteractionQueue BuildQueue(int capacity = 8) =>
        new(Options.Create(new JakapilCaptureOptions { QueueCapacity = capacity }));

    private static CapturedInteraction NewInteraction()
    {
        var now = DateTimeOffset.UtcNow;
        return new CapturedInteraction
        {
            Id = Guid.NewGuid(),
            Timestamp = now,
            DurationMs = 1,
            Correlation = new CorrelationSignals { ObservedAt = now },
            Request = new CapturedRequest { Method = "GET", RawPath = "/x", Headers = new Dictionary<string, string>(), RouteParameters = [] },
            Response = new CapturedResponse { StatusCode = 200, Headers = new Dictionary<string, string>() },
            Endpoint = new EndpointInfo { RouteTemplate = "/x" },
        };
    }

    /// <summary><c>Clear</c> drains all items waiting in the queue — afterwards the reader finds no items.</summary>
    [Fact]
    public async Task Clear_DrainsAllQueuedItems()
    {
        var queue = BuildQueue();
        for (var i = 0; i < 3; i++)
        {
            await queue.EnqueueAsync(NewInteraction());
        }

        queue.Clear();

        Assert.False(queue.Reader.TryRead(out _));
    }

    /// <summary><c>Clear</c> does NOT affect the DropOldest counter (<see cref="CapturedInteractionQueue.DroppedCount"/>)
    /// — this counter tracks only capacity-overflow drops, not the remote-shutdown drop.</summary>
    [Fact]
    public async Task Clear_DoesNotChangeDroppedCount()
    {
        var queue = BuildQueue();
        await queue.EnqueueAsync(NewInteraction());
        var before = queue.DroppedCount;

        queue.Clear();

        Assert.Equal(before, queue.DroppedCount);
    }

    /// <summary>Calling <c>Clear</c> on an empty queue is safe (no-op) and does not throw.</summary>
    [Fact]
    public void Clear_OnEmptyQueue_IsSafeAndDoesNotThrow()
    {
        var queue = BuildQueue();

        var exception = Record.Exception(() => queue.Clear());

        Assert.Null(exception);
    }

    /// <summary>After <c>Clear</c> the queue is reusable — a new <c>Enqueue</c> can be read normally.</summary>
    [Fact]
    public async Task Clear_QueueIsReusableAfterwards()
    {
        var queue = BuildQueue();
        await queue.EnqueueAsync(NewInteraction());
        queue.Clear();

        var fresh = NewInteraction();
        await queue.EnqueueAsync(fresh);

        Assert.True(queue.Reader.TryRead(out var read));
        Assert.Equal(fresh.Id, read!.Id);
    }
}
