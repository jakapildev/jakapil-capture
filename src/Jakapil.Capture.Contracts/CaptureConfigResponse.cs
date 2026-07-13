namespace Jakapil.Capture.Contracts;

/// <summary>
/// <c>GET /ingest/config</c> response (Phase 14 M4): the environment's capture on/off state + revision
/// counter + recommended poll interval, which the SDK polls periodically. Like the ingest DTO, this is
/// a public version contract (ARCH §5.2) — **additive-only**: no field removal/renaming, new fields are
/// added optionally.
/// </summary>
public sealed record CaptureConfigResponse
{
    /// <summary>Whether traffic capture is enabled server-side for the environment this ingest key is bound to.</summary>
    public required bool Enabled { get; init; }

    /// <summary>The capture configuration revision counter; incremented whenever the environment's toggle changes.</summary>
    public required long Revision { get; init; }

    /// <summary>How often (in seconds) the SDK should re-poll this endpoint; server-driven.</summary>
    public required int PollIntervalSeconds { get; init; }
}
