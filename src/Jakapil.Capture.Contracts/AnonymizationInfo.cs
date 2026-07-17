namespace Jakapil.Capture.Contracts;

/// <summary>
/// Wire metadata describing which anonymization scheme (and key version) produced this interaction's
/// fingerprint/synthetic/tombstone values (ADR-0002 §10, Phase 15b-1). The customer's HMAC key itself is
/// <b>never</b> included here or anywhere else in the wire contract — only which scheme+version was used, so
/// the server can reason about key-rotation boundaries (a different <see cref="KeyVersion"/> is a separate,
/// non-correlating key space; ADR §14).
/// </summary>
/// <remarks>
/// Like the rest of <see cref="CapturedInteraction"/>, this is additive: absence of
/// <see cref="CapturedInteraction.Anon"/> means the interaction was produced by a legacy SDK that does not
/// anonymize (plaintext) — the server treats that as a distinct, known signal (ADR §10), not an error.
/// </remarks>
public sealed record AnonymizationInfo
{
    /// <summary>The anonymization scheme identifier (e.g. <c>"hmac-sha256-v1"</c>).</summary>
    public required string Scheme { get; init; }

    /// <summary>The HMAC key version used to derive this interaction's fingerprints/synthetic values
    /// (ADR §14 — a rotation boundary: different versions are separate correlation spaces).</summary>
    public required int KeyVersion { get; init; }
}
