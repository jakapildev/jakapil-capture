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

    /// <summary>The identity's claims: a type→value mapping. When a claim type has more than one value (e.g.
    /// two separate <c>role</c> claims on a multi-role user), this holds only the LAST one encountered — see
    /// <see cref="MultiValuedClaims"/> for the full set in that case.</summary>
    public IReadOnlyDictionary<string, string> Claims { get; init; } = new Dictionary<string, string>();

    /// <summary>
    /// The full set of values for every claim type that has more than one value on the identity — the case
    /// <see cref="Claims"/> alone cannot represent (it keeps one value per type). <c>null</c> when no claim
    /// type on this identity has more than one value, so a consumer should read <see cref="Claims"/> directly
    /// in the common case rather than checking an always-empty map. Values are kept in claim encounter order
    /// (not sorted); a claim type with only a single value is NOT duplicated here, only in <see cref="Claims"/>.
    /// </summary>
    public IReadOnlyDictionary<string, IReadOnlyList<string>>? MultiValuedClaims { get; init; }
}
