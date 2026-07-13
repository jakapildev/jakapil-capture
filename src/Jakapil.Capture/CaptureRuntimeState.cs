namespace Jakapil.Capture;

/// <summary>
/// The remote (server-polled) capture on/off state shared across the SDK process (Phase 14 M4).
/// </summary>
/// <remarks>
/// <see cref="JakapilCaptureMiddleware"/> reads it on every request, and <see cref="CaptureConfigPollWorker"/>
/// updates it periodically. The effective capture state is ALWAYS <c>options.Enabled &amp;&amp; runtimeState.Enabled</c>
/// — a local <c>Enabled=false</c> is a hard floor that can never be turned on remotely (security). When the config
/// endpoint is unreachable, the poll worker does NOT change this state (the last known state is preserved); this is
/// why the initial value is <c>true</c> — until the first successful poll, the behavior is the same as before M4
/// (using only <c>options.Enabled</c>).
/// </remarks>
public interface ICaptureRuntimeState
{
    /// <summary>The last known capture state from the server (or the default <c>true</c> if never polled).</summary>
    bool Enabled { get; }
}

/// <summary>
/// Thread-safe, in-memory singleton implementation of <see cref="ICaptureRuntimeState"/>.
/// </summary>
/// <remarks>
/// <see cref="bool"/> reads/writes are already atomic in the CLR; no additional lock is needed. Only
/// <see cref="CaptureConfigPollWorker"/> writes, and <see cref="JakapilCaptureMiddleware"/> reads (concurrently,
/// from request threads).
/// </remarks>
public sealed class CaptureRuntimeState : ICaptureRuntimeState
{
    private volatile bool _enabled = true;

    /// <inheritdoc />
    public bool Enabled => _enabled;

    /// <summary>Updates the state (called only by <see cref="CaptureConfigPollWorker"/>).</summary>
    internal void SetEnabled(bool enabled) => _enabled = enabled;
}
