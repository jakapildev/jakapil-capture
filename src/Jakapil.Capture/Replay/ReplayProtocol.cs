namespace Jakapil.Capture.Replay;

/// <summary>Wire-format constants for ADR-0003's signed-replay protocol, shared by the header parser, the
/// canonical-string builder, and the middleware's masking-confirmation response header.</summary>
internal static class ReplayProtocol
{
    /// <summary>The request header the Jakapil Runner attaches to a signed replay request (ADR-0003 §6.3).</summary>
    public const string RequestHeaderName = "X-Jakapil-Replay";

    /// <summary>The masking-confirmation response header (ADR-0003 §4/INV-B1) — its presence is what lets the
    /// Jakapil cloud side decide whether a captured-during-replay response body is safe to persist.</summary>
    public const string MaskedResponseHeaderName = "X-Jakapil-Masked";

    /// <summary>The only signature algorithm this SDK version verifies (ADR-0003 §6.1: ECDSA P-256 + SHA-256,
    /// JOSE name <c>ES256</c>). Any other <c>alg</c> value in the header is an unknown algorithm — treated as an
    /// invalid signature (fail-safe, never a crash) so a future SDK/Runner algorithm upgrade degrades safely on
    /// old SDKs instead of breaking them.</summary>
    public const string SupportedAlgorithm = "ES256";

    /// <summary>The only header protocol version this SDK version understands (ADR-0003 §6.3 <c>v=1</c>).</summary>
    public const string SupportedVersion = "1";

    /// <summary>The first line of the canonical signature string (ADR-0003 §6.2) — a fixed literal, not derived
    /// from anything in the request, so the same protocol name can never collide with a signature computed for
    /// a different purpose.</summary>
    public const string CanonicalPrefix = "jakapil-replay-v1";
}
