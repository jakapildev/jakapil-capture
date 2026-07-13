namespace Jakapil.Capture.Contracts;

/// <summary>
/// The identity extracted from the request's <c>ClaimsPrincipal</c> (wire contract) — a correlation
/// signal and the basis of the authentication-flow model. The wire counterpart of
/// <c>Jakapil.Core.Capture.IdentityInfo</c>.
/// </summary>
public sealed record IdentityInfo
{
    /// <summary>Whether the request is authenticated.</summary>
    public required bool IsAuthenticated { get; init; }

    /// <summary>The authentication scheme (e.g. <c>Bearer</c>, <c>Cookies</c>).</summary>
    public string? AuthenticationScheme { get; init; }

    /// <summary>The subject's identity (from the <c>sub</c> / <c>NameIdentifier</c> claim).</summary>
    public string? SubjectId { get; init; }

    /// <summary>The user name.</summary>
    public string? UserName { get; init; }

    /// <summary>The identity's claims: a type→value mapping.</summary>
    public IReadOnlyDictionary<string, string> Claims { get; init; } = new Dictionary<string, string>();
}
