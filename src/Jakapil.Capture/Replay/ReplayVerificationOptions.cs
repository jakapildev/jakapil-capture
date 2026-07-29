namespace Jakapil.Capture.Replay;

/// <summary>
/// Configuration for verifying signed replay requests from the Jakapil Runner (ADR-0003). When a request
/// carries a valid <c>X-Jakapil-Replay</c> signature, <see cref="JakapilCaptureMiddleware"/> suppresses capture
/// for that request entirely and masks the response body on the way out — same key/scope/classification as
/// ordinary capture-side anonymization, except <c>FlowFingerprint</c> leaves, which are left as their live
/// value so the runner's scenario-chain binding keeps working (ADR-0003 §5). When the header is absent or does
/// not verify, behavior is IDENTICAL to today: no masking, no capture suppression, no error (INV-B3).
/// </summary>
/// <remarks>
/// This is the ADR's "ortam bazlı açma/kapama" (per-environment on/off) knob: leave <see cref="PublicKeys"/>
/// empty (the default) in any environment the Runner never targets, and replay verification is a guaranteed,
/// zero-cost no-op — a request without the header never even reaches the parsing/crypto code path.
/// </remarks>
public sealed class ReplayVerificationOptions
{
    /// <summary>Master on/off switch for replay signature verification. Even when true, verification only
    /// actually runs when at least one entry is present in <see cref="PublicKeys"/> (ADR-0003 §6.5) — this flag
    /// exists as an explicit, single-line way to disable the feature per environment without clearing the key
    /// list (e.g. via environment-specific configuration overrides).</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// The Jakapil Runner's ECDSA P-256 public key(s), each as SubjectPublicKeyInfo — PEM
    /// (<c>-----BEGIN PUBLIC KEY-----...-----END PUBLIC KEY-----</c>) or a single-line base64(DER) string
    /// (ADR-0003 §6.5). Multiple keys may be valid AT THE SAME TIME — this is the rotation window: the header's
    /// <c>kid</c> selects which configured key verifies a given request, and nothing is removed automatically —
    /// retire a rotated-out key by deleting its entry once the rotation window has closed.
    /// </summary>
    public string[] PublicKeys { get; set; } = [];

    /// <summary>
    /// The Jakapil tenant id this deployment expects a valid replay signature to have been issued for, matched
    /// against the header's <c>tid</c> field (ordinal, case-insensitive). When null/empty (the default), this
    /// check is SKIPPED entirely — see the class remarks for the residual risk that leaves.
    /// </summary>
    /// <remarks>
    /// Deliberately NOT <see cref="Anonymization.AnonymizationScope.TenantId"/>: that field feeds HMAC domain
    /// separation for every anonymization digest (ADR-0002 §6.2) — changing it changes every synthetic value a
    /// customer has ever seen. Replay identity binding is a different concern with a different (and looser)
    /// correctness bar, so it gets its own, independently optional, field here.
    /// </remarks>
    public string? ExpectedTenantId { get; set; }

    /// <summary>
    /// The Jakapil environment id this deployment expects a valid replay signature to have been issued for,
    /// matched against the header's <c>eid</c> field (ordinal, case-insensitive). When null/empty (the
    /// default), this check is SKIPPED entirely.
    /// </summary>
    /// <remarks>
    /// <b>Residual risk when left unconfigured (state this plainly):</b> the key ring is per-project, so an
    /// unconfigured deployment is not wide open — but WITHOUT <see cref="ExpectedEnvironmentId"/>, a run signed
    /// for one environment (e.g. a staging slot) CAN be replayed against a different instance of the SAME
    /// project that happens to share the same public key (e.g. another staging slot, or — if the key is ever
    /// reused there — production). Setting this field closes that gap for THIS deployment. The real protection
    /// for production is the explicit <see cref="Enabled"/> switch: a production deployment should keep replay
    /// verification disabled outright (leave <see cref="PublicKeys"/> empty, or set <see cref="Enabled"/> to
    /// false) rather than relying on <see cref="ExpectedEnvironmentId"/> alone to keep replay behavior out of
    /// production traffic.
    /// </remarks>
    public string? ExpectedEnvironmentId { get; set; }

    /// <summary>The allowed clock-skew tolerance applied to the header's <c>ts</c> (timestamp) field (ADR-0003
    /// §7 recommends ±300s). The <c>exp</c> (expiry) field is checked separately, always strictly (no added
    /// tolerance) — it is the request's own stated absolute deadline, not a clock-skew allowance.</summary>
    public TimeSpan ClockSkewTolerance { get; set; } = TimeSpan.FromSeconds(300);

    /// <summary>The bounded capacity of the nonce replay-cache (ADR-0003 §6.6/§7). See
    /// <see cref="ReplayNonceCache"/> for the eviction policy and the trade-off it makes explicit.</summary>
    public int NonceCacheSize { get; set; } = 10_000;

    /// <summary>
    /// The hard cap (bytes) on how much of a live response body a signed replay request is willing to buffer in
    /// order to mask it. Masking a live response (unlike ordinary capture, which only ever produces a
    /// best-effort SIDE COPY) cannot work from a truncated partial copy — the transformed bytes ARE what is
    /// sent back to the caller — so a response that exceeds this cap is sent through UNMASKED and WITHOUT the
    /// masking-confirmation header (fail-safe: an unmaskable body is never silently corrupted, and never
    /// falsely reported as masked).
    /// </summary>
    public int MaxMaskedResponseBytes { get; set; } = 8 * 1024 * 1024;
}

/// <summary>Startup validation for <see cref="ReplayVerificationOptions"/> — validated as part of
/// <see cref="JakapilCaptureOptionsValidator"/> (nested options are checked from the parent's validator, the
/// same pattern <see cref="Anonymization.AnonymizationOptions"/> uses).</summary>
internal static class ReplayVerificationOptionsValidator
{
    /// <summary>Appends any validation failures for <paramref name="options"/> to <paramref name="failures"/>.
    /// Every configured public key is parsed here too — a malformed key fails FAST at host startup rather than
    /// silently never verifying anything at runtime (the "uyarı = hata" build discipline applied to config).</summary>
    public static void Validate(ReplayVerificationOptions options, List<string> failures)
    {
        if (options.ClockSkewTolerance < TimeSpan.Zero)
        {
            failures.Add("The replay clock-skew tolerance (Replay.ClockSkewTolerance) cannot be negative.");
        }

        if (options.NonceCacheSize < 1)
        {
            failures.Add("The replay nonce cache size (Replay.NonceCacheSize) must be positive.");
        }

        if (options.MaxMaskedResponseBytes < 1)
        {
            failures.Add("The replay max masked response size (Replay.MaxMaskedResponseBytes) must be positive.");
        }

        foreach (var publicKey in options.PublicKeys)
        {
            try
            {
                var (_, key) = ReplayKeyRing.LoadKey(publicKey);
                key.Dispose();
            }
            catch (Exception ex) when (ex is FormatException or System.Security.Cryptography.CryptographicException or ArgumentException)
            {
                failures.Add(
                    "A configured replay public key (Replay.PublicKeys) could not be parsed as an ECDSA P-256 " +
                    $"SubjectPublicKeyInfo (PEM or base64-DER): {ex.Message}");
            }
        }
    }
}
