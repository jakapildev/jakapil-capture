using System.Text.Json;
using System.Text.Json.Serialization;

namespace Jakapil.Capture.Contracts;

/// <summary>
/// The wire payload of a single captured HTTP request/response pair — the public, versioned contract
/// the Capture SDK sends to <c>POST /ingest</c>.
/// </summary>
/// <remarks>
/// It deliberately does <b>not</b> reference <c>Jakapil.Core</c> so a customer's process never pulls in
/// the production engine. It mirrors the shape of <c>Jakapil.Core.Capture.CapturedInteraction</c>, so the
/// wire→Core mapping on the collector side is a flat field copy.
/// <para>
/// <b>Versioning:</b> this DTO is additive-only — fields are never removed or renamed, new fields are
/// added optionally. Old SDKs in the field keep sending the old shape; removing a field would silently
/// break their capture.
/// </para>
/// <para>
/// <b>Deliberately left out:</b> outgoing-dependency records (Core's <c>Dependencies</c> /
/// <c>OutgoingDependencyCall</c>) are a payload needed only for mocking; since mocking is not yet
/// supported, they are not part of the base wire contract. When mocking arrives these fields are added
/// back additively, without a breaking change.
/// </para>
/// </remarks>
public sealed record CapturedInteraction
{
    /// <summary>The unique identifier of the interaction.</summary>
    public required Guid Id { get; init; }

    /// <summary>The timestamp at which the request started.</summary>
    public required DateTimeOffset Timestamp { get; init; }

    /// <summary>The duration of the request/response cycle in milliseconds.</summary>
    public required long DurationMs { get; init; }

    /// <summary>Raw correlation signals; consumed by the Core correlation engine after the wire→Core mapping.</summary>
    public required CorrelationSignals Correlation { get; init; }

    /// <summary>The captured request.</summary>
    public required CapturedRequest Request { get; init; }

    /// <summary>The captured response.</summary>
    public required CapturedResponse Response { get; init; }

    /// <summary>Route template and endpoint identity; in-process metadata invisible to network-level capture tools.</summary>
    public required EndpointInfo Endpoint { get; init; }

    /// <summary>The identity extracted from the request (null if not authenticated).</summary>
    public IdentityInfo? Identity { get; init; }

    /// <summary>Captured exception information if an exception occurred during the request.</summary>
    public CapturedException? Exception { get; init; }

    /// <summary>Authentication-flow metadata: whether the request carried authentication and which
    /// login/register response produced its token. The raw token is never captured.</summary>
    public AuthBinding? Auth { get; init; }

    /// <summary>Carries fields this contract does not currently recognize (new/experimental) — for forward-compatibility observation, never mapped to Core.</summary>
    /// <remarks>
    /// Unknown fields sent by a newer-versioned SDK accumulate here; the server logs only the field
    /// names (never their values) for observation purposes. If empty it is not serialized, so it does
    /// not break the wire contract.
    /// </remarks>
    [JsonExtensionData]
    public IDictionary<string, JsonElement>? UnmappedFields { get; init; }
}

/// <summary>The wire representation of a captured HTTP request.</summary>
public sealed record CapturedRequest
{
    /// <summary>The HTTP method.</summary>
    public required string Method { get; init; }

    /// <summary>The raw path of the request (e.g. <c>/api/products/42</c>).</summary>
    public required string RawPath { get; init; }

    /// <summary>The raw query string, if any.</summary>
    public string? QueryString { get; init; }

    /// <summary>The request headers; sensitive values are masked.</summary>
    public required IReadOnlyDictionary<string, string> Headers { get; init; }

    /// <summary>Typed route parameters (e.g. <c>{id}=42</c>, int).</summary>
    public required IReadOnlyList<RouteParameter> RouteParameters { get; init; }

    /// <summary>Parsed query parameters, if any.</summary>
    public IReadOnlyDictionary<string, string>? QueryParameters { get; init; }

    /// <summary>The captured request body, if any.</summary>
    public CapturedBody? Body { get; init; }

    /// <summary>The content type of the request.</summary>
    public string? ContentType { get; init; }
}

/// <summary>The wire representation of a captured HTTP response.</summary>
public sealed record CapturedResponse
{
    /// <summary>The HTTP status code.</summary>
    public required int StatusCode { get; init; }

    /// <summary>The response headers; sensitive values are masked.</summary>
    public required IReadOnlyDictionary<string, string> Headers { get; init; }

    /// <summary>The captured response body, if any.</summary>
    public CapturedBody? Body { get; init; }

    /// <summary>The content type of the response.</summary>
    public string? ContentType { get; init; }

    /// <summary>The <c>Location</c> header (e.g. the resource URI returned by a 201 Created).</summary>
    public string? LocationHeader { get; init; }
}
