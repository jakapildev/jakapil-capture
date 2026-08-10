using System.Diagnostics;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Jakapil.Capture.Contracts;
using Microsoft.AspNetCore.Http;

namespace Jakapil.Capture;

/// <summary>
/// Builds a <see cref="CapturedInteraction"/> (wire contract) from an in-flight <see cref="HttpContext"/> and the
/// request/response bytes the middleware buffered around it. All the in-process semantic richness (route template,
/// typed route parameters, identity, trace ids) is extracted here from the ASP.NET Core request pipeline.
/// </summary>
public static class CaptureBuilder
{
    /// <summary>
    /// The key under which, when a response is re-executed by <c>UseStatusCodePagesWithReExecute</c>, the middleware
    /// stores the ORIGINAL request path in <see cref="HttpContext.Items"/>.
    /// </summary>
    /// <remarks>
    /// This is necessary because by the time this builder runs (after <c>_next</c> completes),
    /// <see cref="HttpContext.GetEndpoint"/> returns the re-executed error endpoint (e.g. <c>/errors/{code}</c>) and
    /// <c>IStatusCodeReExecuteFeature</c> has already been reset to null in the status-code-pages middleware's own
    /// <c>finally</c>. So the middleware snapshots the original path in an <c>OnStarting</c> callback while that
    /// feature is still present and leaves it here. The presence of this key is the reliable indicator of the
    /// "this response was re-executed" signal.
    /// </remarks>
    public const string ReExecutedOriginalPathItemKey = "Jakapil.ReExecutedOriginalPath";

    /// <summary>
    /// Builds a full <see cref="CapturedInteraction"/> from an <see cref="HttpContext"/> and the request/response
    /// bodies the middleware buffered.
    /// </summary>
    /// <remarks>
    /// If the response was re-executed by status-code-pages, since <see cref="HttpContext.GetEndpoint"/> now points to
    /// the error endpoint, the endpoint/path fields are determined from the ORIGINAL path the middleware stored; the
    /// captured response (status + body) is still the final response seen by the client, only the endpoint id/path is
    /// corrected. Authentication-flow discovery is performed against the raw request/response before masking, using an
    /// in-memory hash-comparison registry; token text is never persisted.
    /// </remarks>
    public static CapturedInteraction Build(
        HttpContext context,
        DateTimeOffset requestStart,
        long durationMs,
        CapturedBody? requestBody,
        CapturedBody? responseBody,
        Exception? exception,
        JakapilCaptureOptions options,
        IAuthTokenRegistry? authTokens = null)
    {
        var reExecutedOriginalPath = context.Items.TryGetValue(ReExecutedOriginalPathItemKey, out var originalPathObj)
            ? originalPathObj as string
            : null;
        var reExecuted = !string.IsNullOrEmpty(reExecutedOriginalPath);

        var endpoint = reExecuted ? null : context.GetEndpoint();
        var id = Guid.NewGuid();
        var authoritativeIdentity = SelectAuthoritativeIdentity(context.User);
        var subject = authoritativeIdentity is { IsAuthenticated: true } ? FindSubjectId(authoritativeIdentity) : null;

        var auth = authTokens is null ? null : AuthFlowExtractor.ResolveAuthBinding(context, subject, authTokens);
        if (authTokens is not null)
        {
            AuthFlowExtractor.RegisterEmittedTokens(id, subject, responseBody, authTokens);
        }

        return new CapturedInteraction
        {
            Id = id,
            Timestamp = requestStart,
            DurationMs = durationMs,
            Correlation = BuildCorrelation(context, requestStart, options),
            Request = BuildRequest(context, requestBody, endpoint, options, reExecuted ? reExecutedOriginalPath : null),
            Response = BuildResponse(context, responseBody, options),
            Endpoint = reExecuted
                ? new EndpointInfo { RouteTemplate = reExecutedOriginalPath! }
                : RouteSchemaExtractor.BuildEndpointInfo(endpoint, context),
            Identity = BuildIdentity(context.User),
            Exception = exception is null ? null : BuildException(exception),
            Auth = auth,
        };
    }

    /// <summary>Builds a <see cref="CapturedRequest"/>.</summary>
    /// <remarks>If the response was re-executed, the path is taken from the explicitly snapshotted original path and the
    /// route parameters are suppressed, because the current <c>RouteValues</c> belong to the error endpoint (e.g.
    /// <c>{code}=401</c>), not the original request.</remarks>
    private static CapturedRequest BuildRequest(
        HttpContext context, CapturedBody? body, Endpoint? endpoint, JakapilCaptureOptions options,
        string? reExecutedOriginalPath = null)
    {
        var request = context.Request;

        IReadOnlyDictionary<string, string>? queryParameters = null;
        if (request.Query.Count > 0)
        {
            var dict = new Dictionary<string, string>();
            foreach (var (key, value) in request.Query)
            {
                dict[key] = value.ToString();
            }
            queryParameters = dict;
        }

        return new CapturedRequest
        {
            Method = request.Method,
            RawPath = reExecutedOriginalPath ?? request.Path.Value ?? string.Empty,
            QueryString = request.QueryString.HasValue ? request.QueryString.Value : null,
            Headers = HeaderMasking.MaskHeaders(request.Headers, options.SensitiveHeaderNames, options.HeaderCaptureAllowlist),
            RouteParameters = reExecutedOriginalPath is not null ? [] : RouteSchemaExtractor.ExtractRouteParameters(request, endpoint),
            QueryParameters = queryParameters,
            Body = body,
            ContentType = request.ContentType,
        };
    }

    /// <summary>Builds a <see cref="CapturedResponse"/> from the response status, masked headers, body, and the
    /// <c>Location</c> header.</summary>
    private static CapturedResponse BuildResponse(HttpContext context, CapturedBody? body, JakapilCaptureOptions options)
    {
        var response = context.Response;

        return new CapturedResponse
        {
            StatusCode = response.StatusCode,
            Headers = HeaderMasking.MaskHeaders(response.Headers, options.SensitiveHeaderNames, options.HeaderCaptureAllowlist),
            Body = body,
            ContentType = response.ContentType,
            LocationHeader = response.Headers.Location.Count > 0 ? response.Headers.Location.ToString() : null,
        };
    }

    /// <summary>Builds an <see cref="IdentityInfo"/> from a <see cref="ClaimsPrincipal"/> containing the authentication
    /// status, scheme, subject id, user name, and claims; on duplicate claim types, <see cref="IdentityInfo.Claims"/>
    /// keeps the last value (legacy behavior), while every value is preserved in
    /// <see cref="IdentityInfo.MultiValuedClaims"/> (defect K-3: a multi-role user's several <c>role</c> claims used
    /// to collapse to one).</summary>
    /// <remarks>
    /// Returns null if there is no identity. <see cref="IdentityInfo.IsAuthenticated"/>,
    /// <see cref="IdentityInfo.AuthenticationScheme"/>, <see cref="IdentityInfo.UserName"/> and
    /// <see cref="IdentityInfo.SubjectId"/> are all read from the single identity selected by
    /// <see cref="SelectAuthoritativeIdentity"/>, so they describe the same identity. <see cref="IdentityInfo.Claims"/>
    /// is deliberately kept as the merged set across every identity on the principal: a role claim relevant to
    /// matching may live on a different identity than the one that authorised the request, so narrowing the claim
    /// set to the selected identity would lose matching signal the fix is not meant to discard. The walk is a
    /// single pass over <see cref="ClaimsPrincipal.Claims"/>: <c>duplicates</c> stays null and no extra list is
    /// allocated for the common single-valued case; only when a claim TYPE is seen a second time does it start
    /// tracking that type's values (seeding the list from the value already in <c>claims</c>).
    /// </remarks>
    private static IdentityInfo? BuildIdentity(ClaimsPrincipal? user)
    {
        if (user?.Identity is null)
        {
            return null;
        }

        var claims = new Dictionary<string, string>();
        Dictionary<string, List<string>>? duplicates = null;
        foreach (var claim in user.Claims)
        {
            if (duplicates is not null && duplicates.TryGetValue(claim.Type, out var values))
            {
                values.Add(claim.Value);
            }
            else if (claims.ContainsKey(claim.Type))
            {
                (duplicates ??= [])[claim.Type] = [claims[claim.Type], claim.Value];
            }

            claims[claim.Type] = claim.Value;
        }

        IReadOnlyDictionary<string, IReadOnlyList<string>>? multiValuedClaims = null;
        if (duplicates is not null)
        {
            var result = new Dictionary<string, IReadOnlyList<string>>(duplicates.Count);
            foreach (var (claimType, values) in duplicates)
            {
                result[claimType] = values;
            }

            multiValuedClaims = result;
        }

        var identity = SelectAuthoritativeIdentity(user);

        return new IdentityInfo
        {
            IsAuthenticated = identity?.IsAuthenticated ?? user.Identity.IsAuthenticated,
            AuthenticationScheme = identity?.AuthenticationType,
            SubjectId = identity is null ? null : FindSubjectId(identity),
            UserName = identity?.Name ?? user.Identity.Name,
            Claims = claims,
            MultiValuedClaims = multiValuedClaims,
        };
    }

    /// <summary>Selects the identity that authorised the request out of a (possibly multi-identity)
    /// <see cref="ClaimsPrincipal"/>: the first identity for which <see cref="ClaimsIdentity.IsAuthenticated"/> is
    /// true, falling back to the principal's primary identity (<see cref="ClaimsPrincipal.Identity"/>) if none is
    /// authenticated.</summary>
    /// <remarks>
    /// A <see cref="ClaimsPrincipal"/> commonly carries more than one <see cref="ClaimsIdentity"/> — for example an
    /// ASP.NET Core Identity cookie identity alongside a JWT bearer identity added by a second authentication
    /// handler. <see cref="ClaimsPrincipal.Identity"/> only ever returns the <em>first</em> of these, which is not
    /// necessarily the one that actually authorised the request; reading scheme/name from it while reading the
    /// subject id from <c>principal.FindFirst</c> (which searches every identity) can silently mix fields from two
    /// different identities. Selecting deterministically here — in exactly one place — is what makes
    /// <see cref="IdentityInfo.AuthenticationScheme"/>, <see cref="IdentityInfo.UserName"/> and
    /// <see cref="IdentityInfo.SubjectId"/> (and the request/correlation subject) describe the same identity.
    /// </remarks>
    private static ClaimsIdentity? SelectAuthoritativeIdentity(ClaimsPrincipal? user) =>
        user is null ? null : user.Identities.FirstOrDefault(i => i.IsAuthenticated) ?? user.Identity as ClaimsIdentity;

    /// <summary>Finds the subject id on a single identity: the <c>NameIdentifier</c> claim, falling back to
    /// <c>sub</c> (the common claim name for JWTs that were not mapped onto <see cref="ClaimTypes"/>).</summary>
    private static string? FindSubjectId(ClaimsIdentity identity) =>
        identity.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? identity.FindFirst("sub")?.Value;

    /// <summary>Builds a <see cref="CapturedException"/> from an <see cref="Exception"/> containing the type name and message.</summary>
    private static CapturedException BuildException(Exception exception) => new()
    {
        Type = exception.GetType().FullName ?? exception.GetType().Name,
        Message = exception.Message,
        StackTraceRef = null,
    };

    /// <summary>Builds a <see cref="CorrelationSignals"/> by gathering correlation signals from the request (trace/span
    /// ids, subject, session cookie hash, connection id, custom correlation header).</summary>
    private static CorrelationSignals BuildCorrelation(HttpContext context, DateTimeOffset observedAt, JakapilCaptureOptions options)
    {
        var activity = Activity.Current;

        string? customHeader = null;
        foreach (var headerName in options.CorrelationHeaderNames)
        {
            if (context.Request.Headers.TryGetValue(headerName, out var value) && value.Count > 0)
            {
                customHeader = value.ToString();
                break;
            }
        }

        var correlationIdentity = SelectAuthoritativeIdentity(context.User);
        var identitySubject = correlationIdentity is { IsAuthenticated: true } ? FindSubjectId(correlationIdentity) : null;

        return new CorrelationSignals
        {
            TraceId = activity?.TraceId.ToString(),
            SpanId = activity?.SpanId.ToString(),
            ParentSpanId = activity?.ParentSpanId.ToString(),
            SubjectId = identitySubject,
            SessionCookieId = ExtractSessionCookieId(context),
            ClientConnectionId = context.Connection.Id,
            CustomCorrelationHeader = customHeader,
            ObservedAt = observedAt,
        };
    }

    /// <summary>Reads the session cookie (<c>.AspNetCore.Cookies</c>) and returns its SHA-256 hash instead of forwarding
    /// the raw value; null if there is no cookie.</summary>
    private static string? ExtractSessionCookieId(HttpContext context)
    {
        if (!context.Request.Cookies.TryGetValue(".AspNetCore.Cookies", out var cookieValue) || string.IsNullOrEmpty(cookieValue))
        {
            return null;
        }

        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(cookieValue));
        return Convert.ToHexString(hash);
    }
}
