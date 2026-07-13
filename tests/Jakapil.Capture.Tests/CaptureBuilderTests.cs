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
}
