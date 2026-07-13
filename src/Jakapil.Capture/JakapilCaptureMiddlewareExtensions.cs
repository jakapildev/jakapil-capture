using Microsoft.AspNetCore.Builder;

namespace Jakapil.Capture;

/// <summary>
/// Extension methods for registering the Jakapil capture middleware into the ASP.NET Core pipeline.
/// </summary>
public static class JakapilCaptureMiddlewareExtensions
{
    /// <summary>
    /// Adds the Jakapil request/response capture middleware to the pipeline. It must be registered early (right
    /// after routing, before the endpoint executes) so it can observe the resolved endpoint metadata. Requires
    /// that <c>AddJakapilCapture</c> has been called on the service collection.
    /// </summary>
    public static IApplicationBuilder UseJakapilCapture(this IApplicationBuilder builder)
        => builder.UseMiddleware<JakapilCaptureMiddleware>();
}
