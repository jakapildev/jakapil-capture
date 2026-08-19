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
    /// <summary>The anonymization scheme identifier (e.g. <c>"hmac-sha256-v2"</c>).</summary>
    public required string Scheme { get; init; }

    /// <summary>The HMAC key version used to derive this interaction's fingerprints/synthetic values
    /// (ADR §14 — a rotation boundary: different versions are separate correlation spaces).</summary>
    public required int KeyVersion { get; init; }

    /// <summary>
    /// The domain-separation scope the SDK actually derived every digest under: the scope-reference half of
    /// the ingest key (<c>jk_&lt;scopeRef&gt;_&lt;secret&gt;</c>), sent raw.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Sent raw rather than hashed on purpose. It is not secret — it travels inside the ingest key on every
    /// request and the server already stores it alongside the environment it labels — so hashing would buy no
    /// confidentiality while making the server-side comparison inexact.
    /// </para>
    /// <para>
    /// <b>Optional by contract.</b> Nullable and non-required so that payloads from SDK versions predating
    /// this field still deserialize (the wire contract is append-only). <c>null</c> means "an older SDK that
    /// derived its digests under a locally configured scope", not an error.
    /// </para>
    /// </remarks>
    public string? ScopeRef { get; init; }
}
