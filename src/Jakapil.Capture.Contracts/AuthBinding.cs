namespace Jakapil.Capture.Contracts;

/// <summary>
/// Wire contract carrying how a request's authentication relates to the flow that produced its token;
/// the wire counterpart of <c>Jakapil.Core.Capture.AuthBinding</c>.
/// </summary>
/// <remarks>
/// The raw token is <b>never</b> transmitted: the Authorization header stays masked, and this binding
/// is discovered at capture time via an in-memory, hash-comparison match against a prior response's
/// token leaf. <see cref="SourceInteractionId"/> / <see cref="SourceFieldPath"/> point to the
/// login/register response field the bearer token came from, so the Core data-flow engine can derive
/// the <c>login.$token -&gt; authed.Authorization</c> edge without ever seeing the value.
/// </remarks>
public sealed record AuthBinding
{
    /// <summary>The request carried an <c>Authorization: Bearer</c> (or similar) credential.</summary>
    public required bool AuthBearing { get; init; }

    /// <summary>The authentication scheme observed on the request (e.g. <c>Bearer</c>).</summary>
    public string? Scheme { get; init; }

    /// <summary>The interaction whose response produced the token this request carries (null if unknown).</summary>
    public Guid? SourceInteractionId { get; init; }

    /// <summary>The JSONPath of the token leaf in the source response (e.g. <c>$.token</c>).</summary>
    public string? SourceFieldPath { get; init; }

    /// <summary>The subject the source login resolved to — taken from the response identity; used to
    /// re-attribute anonymous login/register interactions back to the correct user.</summary>
    public string? SubjectId { get; init; }
}
