namespace Jakapil.Capture.Anonymization;

/// <summary>
/// Configuration for capture-side field anonymization (ADR-0002, Phase 15c): which HMAC key/version derives
/// fingerprints and synthetic values, whether a missing key is a startup error, and per-field classification
/// overrides.
/// </summary>
/// <remarks>
/// <para>
/// <b>The raw key is never a property here.</b> Only the NAME of the environment variable it lives in is
/// configured (<see cref="KeyEnvironmentVariable"/>); <see cref="Anonymizer"/> reads the actual key bytes from
/// the process environment once at startup. This keeps the secret out of this (and any bound appsettings)
/// options object entirely, so it can never be accidentally logged, serialized, or checked into a config file.
/// </para>
/// <para>
/// <b>The domain-separation scope is not configured here either.</b> It is derived from the scope-reference
/// half of the ingest key (<c>jk_&lt;scopeRef&gt;_&lt;secret&gt;</c>), so it is always the real, server-known
/// identity of the target environment and can no longer be left blank by accident.
/// </para>
/// </remarks>
public sealed class AnonymizationOptions
{
    /// <summary>The default environment variable name the key is read from.</summary>
    public const string DefaultKeyEnvironmentVariable = "JAKAPIL_ANON_KEY";

    /// <summary>Name of the environment variable holding the HMAC anonymization key (raw UTF-8 text). Change
    /// this only if the host's secret-management convention requires a different variable name — never set
    /// the key value itself anywhere in this options object.</summary>
    public string KeyEnvironmentVariable { get; set; } = DefaultKeyEnvironmentVariable;

    /// <summary>The HMAC key version tag written into every fingerprint envelope (ADR §14 — a rotation
    /// boundary: a different version is a separate, non-correlating key space). Must be non-negative.</summary>
    public int KeyVersion { get; set; } = 1;

    /// <summary>
    /// When <c>true</c> (the default), starting the host without the anonymization key configured is a
    /// validation error rather than a silent downgrade to plaintext capture.
    /// </summary>
    /// <remarks>
    /// The default is deliberately fail-closed: with no key, capture would ship raw production request and
    /// response data to the collector, and a log warning is far too easy to miss. Set this to <c>false</c> only
    /// as a conscious, documented decision — for example a local sandbox with no real data in it.
    /// </remarks>
    public bool RequireAnonymization { get; set; } = true;

    /// <summary>Customer field→class overrides (ADR §5 priority #1 — always wins over the built-in rules).
    /// Keys are field names, matched case-insensitively.</summary>
    public IDictionary<string, FieldClass> FieldPolicy { get; set; } = new Dictionary<string, FieldClass>(StringComparer.OrdinalIgnoreCase);

    /// <summary>The domain used for synthesized email addresses (ADR §7 — the real domain is NEVER preserved).
    /// Defaults to <c>example.com</c>; a customer may point this at their own staging/test domain.</summary>
    public string SyntheticEmailDomain { get; set; } = "example.com";
}
