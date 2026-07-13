using System.Text.Json;
using Jakapil.Capture.Contracts;
using Microsoft.AspNetCore.Http;

namespace Jakapil.Capture;

/// <summary>
/// Extracts authentication-flow signals from request/response pairs: resolves which login/register response
/// produced the raw <c>Authorization</c> header via <see cref="IAuthTokenRegistry"/>, and records the newly
/// emitted tokens from response bodies into the same registry.
/// </summary>
/// <remarks>
/// The raw token text never leaves this type; only a hash-keyed mapping is used.
/// </remarks>
internal static class AuthFlowExtractor
{
    /// <summary>Reads the request's raw <c>Authorization: Bearer</c> (before masking) and resolves which
    /// login/register response produced it via the hash-keyed registry.</summary>
    /// <remarks>The raw token never leaves this method.</remarks>
    public static AuthBinding? ResolveAuthBinding(HttpContext context, string? requestSubject, IAuthTokenRegistry authTokens)
    {
        if (!context.Request.Headers.TryGetValue("Authorization", out var authHeader) || authHeader.Count == 0)
        {
            return null;
        }

        var raw = authHeader.ToString();
        var space = raw.IndexOf(' ');
        var scheme = space > 0 ? raw[..space] : raw;
        var credential = space > 0 ? raw[(space + 1)..].Trim() : string.Empty;

        var source = credential.Length > 0 ? authTokens.Lookup(credential) : null;
        return new AuthBinding
        {
            AuthBearing = true,
            Scheme = scheme,
            SourceInteractionId = source?.SourceInteractionId,
            SourceFieldPath = source?.FieldPath,
            SubjectId = source?.SubjectId ?? requestSubject,
        };
    }

    /// <summary>Registers every token-role leaf in this response body so that a subsequent authenticated request
    /// can be bound to it.</summary>
    /// <remarks>Only the hash is stored; the token value is discarded after being hashed. The response's own identity
    /// (a user-id leaf) is taken as the subject the login/register resolves to; no token is registered for an
    /// unparseable body.</remarks>
    public static void RegisterEmittedTokens(Guid id, string? subject, CapturedBody? responseBody, IAuthTokenRegistry authTokens)
    {
        if (responseBody is not { Kind: BodyKind.Json, Truncated: false, Text: { Length: > 0 } text })
        {
            return;
        }

        try
        {
            using var doc = JsonDocument.Parse(text);
            var responseSubject = subject ?? ResponseSubject(doc.RootElement);
            WalkTokens(doc.RootElement, "$", id, responseSubject, authTokens);
        }
        catch (JsonException)
        {
        }
    }

    /// <summary>Recursively walks a JSON element and registers every string leaf whose name denotes a token,
    /// accumulating the JSONPath (e.g. <c>$.token</c>) as the path.</summary>
    private static void WalkTokens(JsonElement element, string path, Guid id, string? subject, IAuthTokenRegistry authTokens)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                foreach (var prop in element.EnumerateObject())
                {
                    if (prop.Value.ValueKind == JsonValueKind.String && IsTokenName(prop.Name))
                    {
                        var value = prop.Value.GetString();
                        if (!string.IsNullOrEmpty(value))
                        {
                            authTokens.Register(value, id, path + "." + prop.Name, subject);
                        }
                    }
                    else
                    {
                        WalkTokens(prop.Value, path + "." + prop.Name, id, subject, authTokens);
                    }
                }

                break;

            case JsonValueKind.Array:
                var i = 0;
                foreach (var item in element.EnumerateArray())
                {
                    WalkTokens(item, path + "[" + i + "]", id, subject, authTokens);
                    i++;
                }

                break;
        }
    }

    /// <summary>Resolves the subject id from a response root: returns the first found of the <c>userId</c>,
    /// <c>userID</c>, <c>sub</c> or <c>id</c> fields.</summary>
    private static string? ResponseSubject(JsonElement root)
    {
        if (root.ValueKind != JsonValueKind.Object)
        {
            return null;
        }

        foreach (var name in new[] { "userId", "userID", "sub", "id" })
        {
            if (root.TryGetProperty(name, out var el))
            {
                return el.ValueKind == JsonValueKind.String ? el.GetString() : el.GetRawText();
            }
        }

        return null;
    }

    /// <summary>Reports whether a field name denotes a token (<c>token</c>, <c>jwt</c>,
    /// <c>accessToken</c>, <c>access_token</c>).</summary>
    private static bool IsTokenName(string name)
    {
        var n = name.ToLowerInvariant();
        return n.Contains("token") || n.Contains("jwt");
    }
}
