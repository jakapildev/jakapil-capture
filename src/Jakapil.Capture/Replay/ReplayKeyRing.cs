using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;
using Jakapil.Capture.Anonymization;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Jakapil.Capture.Replay;

/// <summary>Read-only lookup of the Jakapil Runner's configured ECDSA P-256 public keys, keyed by <c>kid</c>
/// (ADR-0003 §6.3/§6.5).</summary>
/// <remarks>Public only because it is a constructor parameter of the publicly-constructed
/// <see cref="ReplayVerifier"/> (the .NET DI container requires public constructors/parameter types) — it is
/// not intended to be used directly by host applications.</remarks>
public interface IReplayKeyRing
{
    /// <summary>True when at least one key was successfully loaded. When false, replay verification is a
    /// guaranteed no-op regardless of <see cref="ReplayVerificationOptions.Enabled"/> — there is nothing to
    /// verify a signature against.</summary>
    bool HasKeys { get; }

    /// <summary>Looks up the public key whose <c>kid</c> (ADR-0003 §6.3: the first 8 base64url characters of
    /// SHA-256(SPKI DER bytes)) matches <paramref name="keyId"/>. An unknown <c>kid</c> returns false — the
    /// caller treats that exactly like an invalid signature (INV-B3).</summary>
    bool TryGetKey(string keyId, [NotNullWhen(true)] out ECDsa? key);
}

/// <summary>
/// Loads <see cref="ReplayVerificationOptions.PublicKeys"/> once at construction (this is registered as a
/// singleton) and computes each key's <c>kid</c> up front, so verifying a request is a plain dictionary lookup
/// with no parsing/hashing on the request path.
/// </summary>
/// <remarks>
/// Multiple keys can be valid AT THE SAME TIME by design (ADR-0003 §6.5's rotation window) — this is why the
/// lookup is by <c>kid</c> rather than "the one configured key".
/// <para>
/// A key that fails to parse is logged and SKIPPED rather than thrown from the constructor — the same
/// "never let a bad optional config value crash the host application" posture the anonymization key resolver
/// uses (<see cref="Anonymizer"/>). <see cref="ReplayVerificationOptionsValidator"/> additionally validates
/// every key at host startup (<c>ValidateOnStart</c>) so a malformed key is caught immediately in normal
/// deployments; this constructor's own try/catch is defense in depth for the (rare) path where options are
/// constructed without going through that validator, e.g. in tests.
/// </para>
/// </remarks>
public sealed class ReplayKeyRing : IReplayKeyRing, IDisposable
{
    private readonly Dictionary<string, ECDsa> _keysByKeyId = new(StringComparer.Ordinal);

    public ReplayKeyRing(IOptions<JakapilCaptureOptions> options, ILogger<ReplayKeyRing> logger)
        : this(options.Value.Replay.PublicKeys, logger)
    {
    }

    /// <summary>Test seam: builds the ring directly from a list of SPKI strings, bypassing DI options.</summary>
    internal ReplayKeyRing(IReadOnlyList<string> publicKeys, ILogger logger)
    {
        foreach (var raw in publicKeys)
        {
            try
            {
                var (keyId, key) = LoadKey(raw);
                _keysByKeyId[keyId] = key;
            }
            catch (Exception ex) when (ex is FormatException or CryptographicException or ArgumentException)
            {
                logger.LogWarning(
                    ex,
                    "Jakapil: a configured replay public key could not be loaded and will never verify a " +
                    "signature. It must be a SubjectPublicKeyInfo (PEM or single-line base64-DER) ECDSA P-256 key.");
            }
        }
    }

    public bool HasKeys => _keysByKeyId.Count > 0;

    public bool TryGetKey(string keyId, [NotNullWhen(true)] out ECDsa? key) => _keysByKeyId.TryGetValue(keyId, out key);

    /// <summary>Parses one SPKI public key string (PEM or base64-DER) and derives its <c>kid</c>. Exposed as
    /// <c>internal static</c> so <see cref="ReplayVerificationOptionsValidator"/> can perform the identical
    /// parse at startup without duplicating the logic.</summary>
    internal static (string KeyId, ECDsa Key) LoadKey(string raw)
    {
        var der = DecodeSubjectPublicKeyInfo(raw);

        var ecdsa = ECDsa.Create();
        try
        {
            ecdsa.ImportSubjectPublicKeyInfo(der, out _);
        }
        catch
        {
            ecdsa.Dispose();
            throw;
        }

        var hash = SHA256.HashData(der);
        var keyId = Base64UrlManual.Encode(hash)[..8];
        return (keyId, ecdsa);
    }

    /// <summary>Decodes a public key string into raw SPKI DER bytes, accepting either PEM
    /// (<c>-----BEGIN PUBLIC KEY-----</c>) or a single-line base64(DER) string (ADR-0003 §6.5) — the DER bytes
    /// are needed both for <see cref="ECDsa.ImportSubjectPublicKeyInfo"/> and for the <c>kid</c> hash, so PEM is
    /// decoded by hand here rather than via <c>ECDsa.ImportFromPem</c> (which does not hand the DER bytes back).</summary>
    private static byte[] DecodeSubjectPublicKeyInfo(string raw)
    {
        var trimmed = raw.Trim();
        if (trimmed.Length == 0)
        {
            throw new FormatException("The replay public key is empty.");
        }

        if (!trimmed.StartsWith("-----BEGIN", StringComparison.Ordinal))
        {
            return Convert.FromBase64String(trimmed);
        }

        var body = new StringBuilder();
        foreach (var line in trimmed.Split('\n'))
        {
            var trimmedLine = line.Trim('\r', ' ', '\t');
            if (trimmedLine.Length == 0 || trimmedLine.StartsWith("-----", StringComparison.Ordinal))
            {
                continue;
            }

            body.Append(trimmedLine);
        }

        return Convert.FromBase64String(body.ToString());
    }

    public void Dispose()
    {
        foreach (var key in _keysByKeyId.Values)
        {
            key.Dispose();
        }
    }
}
