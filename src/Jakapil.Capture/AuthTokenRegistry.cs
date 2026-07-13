using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;

namespace Jakapil.Capture;

/// <summary>
/// A process-local mapping from a bearer token's hash to the login/register response that produced it.
/// </summary>
/// <remarks>
/// The raw token is never stored: callers pass the raw value only to <see cref="Register"/>/<see cref="Lookup"/>;
/// these hash the value immediately (SHA-256) and keep the hash as the key. This lets capture discover the
/// <c>login.$token -&gt; authed.Authorization</c> data-flow edge while the Authorization header stays masked and
/// no token text ever reaches disk.
/// </remarks>
public interface IAuthTokenRegistry
{
    /// <summary>Records that <paramref name="rawToken"/> was produced by a response field.</summary>
    void Register(string rawToken, Guid sourceInteractionId, string fieldPath, string? subjectId);

    /// <summary>Resolves a bearer token's source; returns null if it was not seen as a produced token.</summary>
    AuthTokenSource? Lookup(string rawToken);
}

/// <summary>Where an authenticated request's bearer token was produced (never the token value itself).</summary>
public sealed record AuthTokenSource(Guid SourceInteractionId, string FieldPath, string? SubjectId);

/// <inheritdoc />
public sealed class AuthTokenRegistry : IAuthTokenRegistry
{
    /// <summary>Entry limit to prevent unbounded growth in a long-lived capture. Since tokens are unique
    /// JWTs, there can be no collision across users; when the limit is reached, clearing everything only
    /// loses an old token's source (degrading to "authenticated, source unknown"), and never breaks a
    /// match.</summary>
    private const int MaxEntries = 100_000;
    private readonly ConcurrentDictionary<string, AuthTokenSource> _byHash = new(StringComparer.Ordinal);

    public void Register(string rawToken, Guid sourceInteractionId, string fieldPath, string? subjectId)
    {
        if (string.IsNullOrEmpty(rawToken))
        {
            return;
        }

        if (_byHash.Count >= MaxEntries)
        {
            _byHash.Clear();
        }

        _byHash[Hash(rawToken)] = new AuthTokenSource(sourceInteractionId, fieldPath, subjectId);
    }

    public AuthTokenSource? Lookup(string rawToken) =>
        string.IsNullOrEmpty(rawToken) ? null : _byHash.TryGetValue(Hash(rawToken), out var src) ? src : null;

    /// <summary>Hashes a value with SHA-256 and converts it to a hexadecimal string; used as the dictionary key.</summary>
    private static string Hash(string value) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
}
