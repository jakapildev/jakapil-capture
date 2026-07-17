namespace Jakapil.Capture.Anonymization;

/// <summary>
/// Configuration for capture-side field anonymization (ADR-0002, Phase 15c): which HMAC key/version derives
/// fingerprints and synthetic values, the domain-separation scope mixed into every digest, and per-field
/// classification overrides.
/// </summary>
/// <remarks>
/// <b>The raw key is never a property here.</b> Only the NAME of the environment variable it lives in is
/// configured (<see cref="KeyEnvironmentVariable"/>); <see cref="Anonymizer"/> reads the actual key bytes from
/// the process environment once at startup. This keeps the secret out of this (and any bound appsettings)
/// options object entirely, so it can never be accidentally logged, serialized, or checked into a config file.
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

    /// <summary>Domain-separation scope mixed into every digest (ADR §6.2) so two tenants/projects/environments
    /// never collide even if they happen to capture the identical raw production value.</summary>
    public AnonymizationScope Scope { get; set; } = new();

    /// <summary>Customer field→class overrides (ADR §5 priority #1 — always wins over the built-in rules).
    /// Keys are field names, matched case-insensitively.</summary>
    public IDictionary<string, FieldClass> FieldPolicy { get; set; } = new Dictionary<string, FieldClass>(StringComparer.OrdinalIgnoreCase);

    /// <summary>The domain used for synthesized email addresses (ADR §7 — the real domain is NEVER preserved).
    /// Defaults to <c>example.com</c>; a customer may point this at their own staging/test domain.</summary>
    public string SyntheticEmailDomain { get; set; } = "example.com";
}

/// <summary>The tenant/project/environment identity mixed into every digest for domain separation (ADR §6.2).</summary>
public sealed class AnonymizationScope
{
    /// <summary>The Jakapil tenant identifier.</summary>
    public string TenantId { get; set; } = string.Empty;

    /// <summary>The Jakapil project identifier.</summary>
    public string ProjectId { get; set; } = string.Empty;

    /// <summary>The environment name (e.g. <c>staging</c>, <c>production</c>).</summary>
    public string Environment { get; set; } = string.Empty;
}
