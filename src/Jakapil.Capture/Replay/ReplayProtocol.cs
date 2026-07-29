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

    /// <summary>The <c>body=</c> value of the masking-confirmation header (ADR-0003 §5 revision, "non-JSON
    /// pass-through") declaring that the replay response body was forwarded to the Runner byte-for-byte,
    /// unmasked, because its <c>Content-Type</c> was not JSON — mirroring capture-time
    /// <c>Anonymizer.TransformBody</c>'s own non-JSON pass-through (there is no safe, general way to anonymize an
    /// arbitrary text/binary blob without a schema). This is the ONLY non-default <c>body=</c> value this SDK
    /// version ever emits; a JSON-masked body OMITS the field entirely rather than emitting a <c>body=masked</c>
    /// counterpart — see <c>JakapilCaptureMiddleware.SetMaskedHeader</c>'s remarks for why absence, not an
    /// explicit "masked" token, is the default.</summary>
    public const string UnmaskedNonJsonBodyDisposition = "unmasked-nonjson";
}
