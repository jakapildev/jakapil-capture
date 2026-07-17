namespace Jakapil.Capture.Anonymization;

/// <summary>
/// The field classes ADR-0002 §2 defines for capture-side anonymization output. Every JSON leaf, route
/// parameter, query parameter, and allowlisted header value is classified into exactly one of these before
/// leaving the customer's process.
/// </summary>
public enum FieldClass
{
    /// <summary>Low-cardinality/measure value that is never personal data; sent unchanged (ADR §2/§5).</summary>
    SafeLiteral,

    /// <summary>Flow-identity value (id/ref/key); replaced by an irreversible HMAC digest wrapped in the
    /// <c>fp:</c> envelope so equal production values still correlate (ADR §6).</summary>
    FlowFingerprint,

    /// <summary>Personal data; replaced by a deterministic synthetic value (ADR §7).</summary>
    SyntheticPii,

    /// <summary>Secret (password/token/cookie/API key); replaced by a digest-free, typed <c>jkp:tomb:</c>
    /// marker — never fingerprinted, because low-entropy secrets are vulnerable to dictionary attack if the
    /// HMAC key ever leaks (ADR §8, INV-A3).</summary>
    SecretTombstone,

    /// <summary>Value entirely withheld. Reachable only via an explicit customer <c>FieldPolicy</c> override —
    /// never a default classification outcome.</summary>
    Dropped,
}
