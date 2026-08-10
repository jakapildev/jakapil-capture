using System.Security.Claims;
using System.Text;
using Jakapil.Capture;
using Jakapil.Capture.Contracts;
using Microsoft.AspNetCore.Http;

namespace Jakapil.Capture.Tests;

public sealed class CaptureBuilderTests
{
    [Theory]
    [InlineData("accessToken")]
    [InlineData("access_token")]
    public void Build_RegistersTokenFieldsInTheAuthTokenRegistry(string fieldName)
    {
        var token = "captured-token";
        var bodyText = $$"""{"{{fieldName}}":"{{token}}"}""";
        var responseBody = new CapturedBody
        {
            Text = bodyText,
            ByteSize = Encoding.UTF8.GetByteCount(bodyText),
            Kind = BodyKind.Json,
            Truncated = false,
        };
        var registry = new AuthTokenRegistry();

        var interaction = CaptureBuilder.Build(
            new DefaultHttpContext(),
            DateTimeOffset.UtcNow,
            durationMs: 1,
            requestBody: null,
            responseBody: responseBody,
            exception: null,
            options: new JakapilCaptureOptions(),
            authTokens: registry);

        var source = Assert.IsType<AuthTokenSource>(registry.Lookup(token));
        Assert.Equal(interaction.Id, source.SourceInteractionId);
        Assert.Equal("$." + fieldName, source.FieldPath);
    }

    /// <summary>Regression test for defect K-1: a <see cref="ClaimsPrincipal"/> carrying more than one
    /// <see cref="ClaimsIdentity"/> (e.g. an unauthenticated cookie identity added first, plus an authenticated
    /// JWT identity added second — a common ASP.NET Core shape) must have its scheme, user name and subject id all
    /// read from the identity that actually authorised the request, not from whichever identity happens to be
    /// first in the collection.</summary>
    [Fact]
    public void Build_MultipleIdentities_ReadsSchemeUserNameAndSubjectFromTheAuthenticatedIdentity()
    {
        var cookieIdentity = new ClaimsIdentity();
        cookieIdentity.AddClaim(new Claim("tenant", "acme"));

        var jwtIdentity = new ClaimsIdentity(
            [
                new Claim(ClaimTypes.NameIdentifier, "jwt-subject-1"),
                new Claim(ClaimTypes.Name, "jwt-user"),
                new Claim(ClaimTypes.Role, "Admin"),
            ],
            authenticationType: "Bearer");

        var context = new DefaultHttpContext { User = new ClaimsPrincipal([cookieIdentity, jwtIdentity]) };

        var interaction = CaptureBuilder.Build(
            context,
            DateTimeOffset.UtcNow,
            durationMs: 1,
            requestBody: null,
            responseBody: null,
            exception: null,
            options: new JakapilCaptureOptions());

        Assert.NotNull(interaction.Identity);
        Assert.True(interaction.Identity!.IsAuthenticated);
        Assert.Equal("Bearer", interaction.Identity.AuthenticationScheme);
        Assert.Equal("jwt-user", interaction.Identity.UserName);
        Assert.Equal("jwt-subject-1", interaction.Identity.SubjectId);

        // Claims stay merged across both identities: a role claim on the authorising identity and a claim that
        // only lives on the other identity must both be present.
        Assert.Equal("Admin", interaction.Identity.Claims[ClaimTypes.Role]);
        Assert.Equal("acme", interaction.Identity.Claims["tenant"]);
    }

    /// <summary>Pins the harder case actually measured live against eShopOnWeb: BOTH identities on the principal
    /// are authenticated — an ASP.NET Core Identity cookie identity (<c>"Identity.Application"</c>) and a JWT
    /// bearer identity (<c>"AuthenticationTypes.Federation"</c>) added by a second authentication handler on the
    /// same request. <see cref="CaptureBuilder"/> selects the first authenticated identity — here, the cookie
    /// identity — as authoritative. Selecting the first authenticated identity is a documented limitation, NOT an
    /// assertion that it is the identity that actually authorised the request: <see cref="HttpContext"/> alone
    /// does not reveal which of several authenticated identities did, and inferring it from the raw
    /// <c>Authorization</c> header would couple identity capture to transport details. What this test pins is
    /// that <see cref="IdentityInfo.AuthenticationScheme"/>, <see cref="IdentityInfo.UserName"/> and
    /// <see cref="IdentityInfo.SubjectId"/> now consistently describe ONE identity instead of being silently
    /// mixed across two, and that <see cref="IdentityInfo.Claims"/> stays merged so no matching signal is
    /// lost.</summary>
    [Fact]
    public void Build_TwoAuthenticatedIdentities_SelectsFirstAuthenticatedAndKeepsClaimsMerged()
    {
        var cookieIdentity = new ClaimsIdentity(
            [
                new Claim(ClaimTypes.NameIdentifier, "cookie-subject"),
                new Claim(ClaimTypes.Name, "cookie-user"),
            ],
            authenticationType: "Identity.Application");

        var jwtIdentity = new ClaimsIdentity(
            [
                new Claim(ClaimTypes.NameIdentifier, "jwt-subject"),
                new Claim(ClaimTypes.Name, "jwt-user"),
                new Claim(ClaimTypes.Role, "Administrators"),
            ],
            authenticationType: "AuthenticationTypes.Federation");

        var context = new DefaultHttpContext { User = new ClaimsPrincipal([cookieIdentity, jwtIdentity]) };

        var interaction = CaptureBuilder.Build(
            context,
            DateTimeOffset.UtcNow,
            durationMs: 1,
            requestBody: null,
            responseBody: null,
            exception: null,
            options: new JakapilCaptureOptions());

        Assert.NotNull(interaction.Identity);
        Assert.True(interaction.Identity!.IsAuthenticated);
        Assert.Equal("Identity.Application", interaction.Identity.AuthenticationScheme);
        Assert.Equal("cookie-user", interaction.Identity.UserName);
        Assert.Equal("cookie-subject", interaction.Identity.SubjectId);

        // The role claim lives only on the identity that was NOT selected as authoritative, but Claims stays
        // merged across both identities, so downstream role matching still sees it.
        Assert.Equal("Administrators", interaction.Identity.Claims[ClaimTypes.Role]);
    }

    /// <summary>Regression test for defect K-3: a principal carrying several claims of the SAME type (the
    /// normal shape for a multi-role user — two separate <c>role</c> claims) must have every value preserved
    /// in <see cref="IdentityInfo.MultiValuedClaims"/>, in encounter order. <see cref="IdentityInfo.Claims"/>
    /// keeps its pre-existing last-writer-wins behavior unchanged, so older server versions that only read
    /// <see cref="IdentityInfo.Claims"/> keep working.</summary>
    [Fact]
    public void Build_MultipleClaimsOfSameType_PreservesAllValuesInMultiValuedClaims_ClaimsKeepsLastWriterWins()
    {
        var identity = new ClaimsIdentity(
            [
                new Claim(ClaimTypes.NameIdentifier, "multi-role-subject"),
                new Claim(ClaimTypes.Role, "Admin"),
                new Claim(ClaimTypes.Role, "Auditor"),
            ],
            authenticationType: "Bearer");

        var context = new DefaultHttpContext { User = new ClaimsPrincipal(identity) };

        var interaction = CaptureBuilder.Build(
            context,
            DateTimeOffset.UtcNow,
            durationMs: 1,
            requestBody: null,
            responseBody: null,
            exception: null,
            options: new JakapilCaptureOptions());

        Assert.NotNull(interaction.Identity);
        Assert.Equal("Auditor", interaction.Identity!.Claims[ClaimTypes.Role]);
        Assert.NotNull(interaction.Identity.MultiValuedClaims);
        Assert.Equal(["Admin", "Auditor"], interaction.Identity.MultiValuedClaims![ClaimTypes.Role]);
    }

    /// <summary>Hot-path guarantee: when no claim type on the principal has more than one value,
    /// <see cref="IdentityInfo.MultiValuedClaims"/> stays null — the common single-valued case must not
    /// allocate an always-empty map.</summary>
    [Fact]
    public void Build_NoDuplicateClaimTypes_MultiValuedClaimsIsNull()
    {
        var identity = new ClaimsIdentity(
            [
                new Claim(ClaimTypes.NameIdentifier, "solo-subject"),
                new Claim(ClaimTypes.Role, "Admin"),
            ],
            authenticationType: "Bearer");

        var context = new DefaultHttpContext { User = new ClaimsPrincipal(identity) };

        var interaction = CaptureBuilder.Build(
            context,
            DateTimeOffset.UtcNow,
            durationMs: 1,
            requestBody: null,
            responseBody: null,
            exception: null,
            options: new JakapilCaptureOptions());

        Assert.NotNull(interaction.Identity);
        Assert.Null(interaction.Identity!.MultiValuedClaims);
    }

    /// <summary>Regression guard: a single-identity principal must behave exactly as before the K-1 fix.</summary>
    [Fact]
    public void Build_SingleIdentity_ReadsSchemeUserNameAndSubjectAsBefore()
    {
        var identity = new ClaimsIdentity(
            [
                new Claim(ClaimTypes.NameIdentifier, "solo-subject"),
                new Claim(ClaimTypes.Name, "solo-user"),
            ],
            authenticationType: "Cookies");

        var context = new DefaultHttpContext { User = new ClaimsPrincipal(identity) };

        var interaction = CaptureBuilder.Build(
            context,
            DateTimeOffset.UtcNow,
            durationMs: 1,
            requestBody: null,
            responseBody: null,
            exception: null,
            options: new JakapilCaptureOptions());

        Assert.NotNull(interaction.Identity);
        Assert.True(interaction.Identity!.IsAuthenticated);
        Assert.Equal("Cookies", interaction.Identity.AuthenticationScheme);
        Assert.Equal("solo-user", interaction.Identity.UserName);
        Assert.Equal("solo-subject", interaction.Identity.SubjectId);
    }

    /// <summary>Regression test for defect K-2: a login response minting a token belongs to the subject the
    /// response body names, not to whoever called the endpoint (e.g. a service account, or a stale session still
    /// active on the connection). The following authenticated request carrying that token must be bound to the
    /// response's subject.</summary>
    [Fact]
    public void Build_LoginResponseNamesDifferentUserThanCaller_BindsFollowUpRequestToResponseSubject()
    {
        var registry = new AuthTokenRegistry();
        const string token = "issued-token-for-user-b";
        var loginBodyText = $$"""{"userId":"user-b","accessToken":"{{token}}"}""";
        var loginResponse = new CapturedBody
        {
            Text = loginBodyText,
            ByteSize = Encoding.UTF8.GetByteCount(loginBodyText),
            Kind = BodyKind.Json,
            Truncated = false,
        };

        var callerIdentity = new ClaimsIdentity(
            [new Claim(ClaimTypes.NameIdentifier, "user-a")],
            authenticationType: "Cookies");
        var loginContext = new DefaultHttpContext { User = new ClaimsPrincipal(callerIdentity) };

        CaptureBuilder.Build(
            loginContext,
            DateTimeOffset.UtcNow,
            durationMs: 1,
            requestBody: null,
            responseBody: loginResponse,
            exception: null,
            options: new JakapilCaptureOptions(),
            authTokens: registry);

        var followUpContext = new DefaultHttpContext();
        followUpContext.Request.Headers["Authorization"] = $"Bearer {token}";

        var followUp = CaptureBuilder.Build(
            followUpContext,
            DateTimeOffset.UtcNow,
            durationMs: 1,
            requestBody: null,
            responseBody: null,
            exception: null,
            options: new JakapilCaptureOptions(),
            authTokens: registry);

        Assert.NotNull(followUp.Auth);
        Assert.Equal("user-b", followUp.Auth!.SubjectId);
    }

    /// <summary>Regression guard for the eShopOnWeb-style flow that must not regress: when a login response
    /// carries no recognisable subject field (no <c>userId</c>/<c>userID</c>/<c>sub</c>/<c>id</c>), the caller's
    /// own identity is still used as the fallback subject for the minted token.</summary>
    [Fact]
    public void Build_LoginResponseWithNoRecognisableSubjectField_FallsBackToCallerSubject()
    {
        var registry = new AuthTokenRegistry();
        const string token = "token-with-no-response-subject";
        var loginBodyText = $$"""{"accessToken":"{{token}}"}""";
        var loginResponse = new CapturedBody
        {
            Text = loginBodyText,
            ByteSize = Encoding.UTF8.GetByteCount(loginBodyText),
            Kind = BodyKind.Json,
            Truncated = false,
        };

        var callerIdentity = new ClaimsIdentity(
            [new Claim(ClaimTypes.NameIdentifier, "caller-subject")],
            authenticationType: "Cookies");
        var loginContext = new DefaultHttpContext { User = new ClaimsPrincipal(callerIdentity) };

        CaptureBuilder.Build(
            loginContext,
            DateTimeOffset.UtcNow,
            durationMs: 1,
            requestBody: null,
            responseBody: loginResponse,
            exception: null,
            options: new JakapilCaptureOptions(),
            authTokens: registry);

        var followUpContext = new DefaultHttpContext();
        followUpContext.Request.Headers["Authorization"] = $"Bearer {token}";

        var followUp = CaptureBuilder.Build(
            followUpContext,
            DateTimeOffset.UtcNow,
            durationMs: 1,
            requestBody: null,
            responseBody: null,
            exception: null,
            options: new JakapilCaptureOptions(),
            authTokens: registry);

        Assert.NotNull(followUp.Auth);
        Assert.Equal("caller-subject", followUp.Auth!.SubjectId);
    }
}
