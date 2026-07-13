namespace Jakapil.Capture.Contracts;

/// <summary>
/// Raw correlation signals (wire contract). No single field here is the "definitive" correlation key on
/// its own — these are combined and weighted downstream by the Core correlation engine. The wire
/// counterpart of <c>Jakapil.Core.Capture.CorrelationSignals</c>.
/// </summary>
public sealed record CorrelationSignals
{
    /// <summary>Distributed trace identifier (<c>Activity.Current</c> / W3C traceparent).</summary>
    public string? TraceId { get; init; }

    /// <summary>The identifier of the current span.</summary>
    public string? SpanId { get; init; }

    /// <summary>The identifier of the parent span.</summary>
    public string? ParentSpanId { get; init; }

    /// <summary>The identity subject; a copy of <c>IdentityInfo.SubjectId</c>.</summary>
    public string? SubjectId { get; init; }

    /// <summary>Cookie-auth-based session identifier (hashed).</summary>
    public string? SessionCookieId { get; init; }

    /// <summary>Client connection identifier (<c>HttpContext.Connection.Id</c>).</summary>
    public string? ClientConnectionId { get; init; }

    /// <summary>Value taken from a custom correlation header (e.g. <c>X-Correlation-ID</c>).</summary>
    public string? CustomCorrelationHeader { get; init; }

    /// <summary>The moment at which the signals were observed.</summary>
    public required DateTimeOffset ObservedAt { get; init; }
}
