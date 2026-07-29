using System.Globalization;
using System.Security.Cryptography;
using Jakapil.Capture.Anonymization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Jakapil.Capture.Replay;

/// <summary>The result of attempting to verify a request's <c>X-Jakapil-Replay</c> header.</summary>
internal sealed class ReplayVerificationOutcome
{
    /// <summary>The request carried no <c>X-Jakapil-Replay</c> header at all (the overwhelmingly common case —
    /// ordinary production/staging traffic). Behaviorally identical to <see cref="Invalid"/> for every caller
    /// (INV-B3: no special behavior either way) — kept as a distinct value only so verification can short-circuit
    /// before touching the request body at all when there is nothing to verify.</summary>
    public static readonly ReplayVerificationOutcome NotSigned = new(isValid: false, reason: "not-signed");

    private ReplayVerificationOutcome(bool isValid, string reason)
    {
        IsValid = isValid;
        Reason = reason;
    }

    /// <summary>True only when every check in ADR-0003 §6.3 passed: known alg, known kid, matching
    /// tenant/environment scope, timestamp within clock-skew tolerance, not expired, nonce not replayed, and
    /// the ECDSA signature verified over the recomputed canonical string.</summary>
    public bool IsValid { get; }

    /// <summary>A short machine-readable reason, logged at Debug level only — never surfaced to the caller as
    /// an error and never changes response behavior (INV-B3: every rejection reason is treated identically).</summary>
    public string Reason { get; }

    public static ReplayVerificationOutcome Invalid(string reason) => new(isValid: false, reason);

    public static ReplayVerificationOutcome Valid() => new(isValid: true, reason: "valid");
}

/// <summary>Verifies a request's signed-replay header against ADR-0003 §6.3's checklist.</summary>
/// <remarks>Public only because it is a constructor parameter of the publicly-constructed
/// <see cref="JakapilCaptureMiddleware"/> (the .NET DI container requires public constructors/parameter
/// types) — it is not intended to be used directly by host applications.</remarks>
public interface IReplayVerifier
{
    /// <summary>
    /// Verifies <paramref name="context"/>'s <c>X-Jakapil-Replay</c> header, if present. Reads and rewinds the
    /// request body (needed to recompute the body-hash field) ONLY when the header is present — an ordinary
    /// request pays zero cost. Never throws: any failure (malformed header, unknown algorithm, expired,
    /// replayed nonce, scope mismatch, bad signature, or any unexpected exception) returns <c>false</c>
    /// (INV-B3 — fail-safe direction is "no special behavior", never an error response). Rejection reasons are
    /// logged at Debug level internally but are never part of this return value — the caller's behavior must
    /// never branch on WHY a signature was rejected, only on valid-or-not.
    /// </summary>
    Task<bool> VerifyAsync(HttpContext context);
}

/// <inheritdoc cref="IReplayVerifier"/>
public sealed class ReplayVerifier : IReplayVerifier
{
    private readonly JakapilCaptureOptions _options;
    private readonly IReplayKeyRing _keyRing;
    private readonly ReplayNonceCache _nonceCache;
    private readonly TimeProvider _timeProvider;
    private readonly ILogger<ReplayVerifier> _logger;

    public ReplayVerifier(
        IOptions<JakapilCaptureOptions> options,
        IReplayKeyRing keyRing,
        ReplayNonceCache nonceCache,
        TimeProvider timeProvider,
        ILogger<ReplayVerifier> logger)
    {
        _options = options.Value;
        _keyRing = keyRing;
        _nonceCache = nonceCache;
        _timeProvider = timeProvider;
        _logger = logger;
    }

    public async Task<bool> VerifyAsync(HttpContext context)
    {
        var outcome = await VerifyWithReasonAsync(context);
        return outcome.IsValid;
    }

    private async Task<ReplayVerificationOutcome> VerifyWithReasonAsync(HttpContext context)
    {
        var replayOptions = _options.Replay;
        if (!replayOptions.Enabled || !_keyRing.HasKeys)
        {
            return ReplayVerificationOutcome.NotSigned;
        }

        if (!context.Request.Headers.TryGetValue(ReplayProtocol.RequestHeaderName, out var headerValues) || headerValues.Count == 0)
        {
            return ReplayVerificationOutcome.NotSigned;
        }

        try
        {
            return await VerifyCoreAsync(context, headerValues.ToString(), replayOptions);
        }
        catch (Exception ex)
        {
            // INV-B3: on ANY doubt — including a bug in this method — the request is ordinary traffic. Never
            // let a verification error propagate into the request pipeline.
            _logger.LogDebug(ex, "Jakapil: replay signature verification threw an exception; treating request as ordinary traffic");
            return ReplayVerificationOutcome.Invalid("exception:" + ex.GetType().Name);
        }
    }

    private async Task<ReplayVerificationOutcome> VerifyCoreAsync(HttpContext context, string headerValue, ReplayVerificationOptions replayOptions)
    {
        var header = ReplayHeader.TryParse(headerValue);
        if (header is null)
        {
            return Reject("malformed-header");
        }

        if (header.Version != ReplayProtocol.SupportedVersion)
        {
            return Reject("unsupported-version");
        }

        if (header.Alg != ReplayProtocol.SupportedAlgorithm)
        {
            return Reject("unknown-alg");
        }

        if (!_keyRing.TryGetKey(header.KeyId, out var key))
        {
            return Reject("unknown-kid");
        }

        // ADR-0003 §6.3: "başka bir kiracının/ortamın geçerli imzası bu hedefte koşum muamelesi göremez" — a
        // signature that is cryptographically valid for a DIFFERENT tenant/environment must not activate replay
        // behavior here. Each check is INDEPENDENTLY optional (ReplayVerificationOptions.ExpectedTenantId /
        // ExpectedEnvironmentId — deliberately NOT AnonymizationOptions.Scope, which feeds HMAC domain
        // separation and must not be repurposed): when a value is configured, the header MUST match it; when
        // it is left unconfigured, that particular check is skipped rather than always-mismatching. See
        // ExpectedEnvironmentId's XML doc for the residual risk this leaves when unconfigured, and why a
        // production deployment's real protection is the Enabled switch, not this comparison.
        if (!string.IsNullOrEmpty(replayOptions.ExpectedTenantId) &&
            !string.Equals(header.TenantId, replayOptions.ExpectedTenantId, StringComparison.OrdinalIgnoreCase))
        {
            return Reject("tenant-mismatch");
        }

        if (!string.IsNullOrEmpty(replayOptions.ExpectedEnvironmentId) &&
            !string.Equals(header.EnvironmentId, replayOptions.ExpectedEnvironmentId, StringComparison.OrdinalIgnoreCase))
        {
            return Reject("environment-mismatch");
        }

        if (!long.TryParse(header.Timestamp, NumberStyles.None, CultureInfo.InvariantCulture, out var timestamp) ||
            !long.TryParse(header.Expiry, NumberStyles.None, CultureInfo.InvariantCulture, out var expiry) ||
            expiry <= timestamp)
        {
            return Reject("malformed-time-fields");
        }

        var nowUnixSeconds = _timeProvider.GetUtcNow().ToUnixTimeSeconds();
        var toleranceSeconds = (long)Math.Max(0, replayOptions.ClockSkewTolerance.TotalSeconds);
        if (Math.Abs(nowUnixSeconds - timestamp) > toleranceSeconds)
        {
            return Reject("clock-skew");
        }

        if (nowUnixSeconds > expiry)
        {
            return Reject("expired");
        }

        byte[] signatureBytes;
        try
        {
            signatureBytes = Base64UrlManual.Decode(header.Signature);
        }
        catch (FormatException)
        {
            return Reject("malformed-signature-encoding");
        }

        var bodyBytes = await BufferRequestBodyAsync(context.Request, _options.MaxInlineBodyBytes);
        if (bodyBytes is null)
        {
            return Reject("body-unreadable-or-too-large");
        }

        var method = context.Request.Method.ToUpperInvariant();
        var route = BuildRawRoute(context.Request);
        var bodyHash = ReplayCanonicalString.ComputeBodyHash(bodyBytes);

        var canonicalBytes = ReplayCanonicalString.Build(
            header.Alg, header.TenantId, header.EnvironmentId, header.RunId, header.RequestId,
            method, route, bodyHash, header.Timestamp, header.Expiry, header.Nonce);

        bool signatureValid;
        try
        {
            signatureValid = key!.VerifyData(canonicalBytes, signatureBytes, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
        catch (CryptographicException)
        {
            // A malformed signature length/format throws rather than returning false; treat identically.
            signatureValid = false;
        }

        if (!signatureValid)
        {
            return Reject("bad-signature");
        }

        // Nonce is only committed to the cache AFTER a successful verify, so a garbage/forged header (anyone
        // can send arbitrary tid/eid/ts/exp/nonce values without the private key) can never burn a nonce slot
        // that a genuine future request might legitimately reuse... though in practice the Runner's nonces are
        // 128-bit random values, so accidental collision is not a realistic concern either way.
        var nonceKey = header.KeyId + ":" + header.Nonce;
        if (!_nonceCache.TryRegister(nonceKey, expiry, nowUnixSeconds))
        {
            return Reject("nonce-replay");
        }

        return ReplayVerificationOutcome.Valid();
    }

    private ReplayVerificationOutcome Reject(string reason)
    {
        _logger.LogDebug("Jakapil: replay signature rejected ({Reason}); request treated as ordinary traffic", reason);
        return ReplayVerificationOutcome.Invalid(reason);
    }

    /// <summary>Buffers the COMPLETE raw request body (up to <paramref name="maxBytes"/>) and rewinds the
    /// stream so <c>_next(context)</c> can still read it in full — mirrors
    /// <c>JakapilCaptureMiddleware.TryCaptureRequestBodyAsync</c>'s buffering pattern, done independently here
    /// so replay verification never depends on capture having run (it must work even when capture is
    /// <see cref="JakapilCaptureOptions.Enabled"/> <c>false</c>). Returns null if the body exceeds
    /// <paramref name="maxBytes"/> or cannot be read — the caller treats that as an invalid signature rather
    /// than throwing (a genuinely-signed request's body can never legitimately need to be dropped, so this
    /// path only affects otherwise-unverifiable oversized/garbage requests).</summary>
    private static async Task<byte[]?> BufferRequestBodyAsync(HttpRequest request, int maxBytes)
    {
        try
        {
            request.EnableBuffering();
            request.Body.Position = 0;

            using var buffer = new MemoryStream();
            var chunk = new byte[8192];
            int read;
            while ((read = await request.Body.ReadAsync(chunk)) > 0)
            {
                buffer.Write(chunk, 0, read);
                if (buffer.Length > maxBytes)
                {
                    request.Body.Position = 0;
                    return null;
                }
            }

            request.Body.Position = 0;
            return buffer.ToArray();
        }
        catch (Exception)
        {
            try
            {
                request.Body.Position = 0;
            }
            catch
            {
                // Best-effort rewind; if even this fails, the request body is in an unusable state regardless
                // of replay verification, so surfacing THIS exception would only obscure the real problem.
            }

            return null;
        }
    }

    /// <summary>Reconstructs the raw, still percent-encoded request-target (path + query) exactly as it
    /// appeared on the wire (ADR-0003 §6.2's <c>route</c> field), preferring
    /// <see cref="IHttpRequestFeature.RawTarget"/> (Kestrel/TestServer populate this from the literal HTTP
    /// request line) and falling back to the decoded <see cref="HttpRequest.Path"/> + <see cref="HttpRequest.QueryString"/>
    /// only if that feature is unavailable.</summary>
    private static string BuildRawRoute(HttpRequest request)
    {
        var rawTarget = request.HttpContext.Features.Get<IHttpRequestFeature>()?.RawTarget;
        if (!string.IsNullOrEmpty(rawTarget))
        {
            return rawTarget;
        }

        return (request.Path.Value ?? string.Empty) + request.QueryString.Value;
    }
}
