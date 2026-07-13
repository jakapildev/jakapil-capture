using Jakapil.Capture.Contracts;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Routing.Patterns;

namespace Jakapil.Capture;

/// <summary>
/// Extracts capture's semantic route/schema fields from an ASP.NET Core <see cref="Endpoint"/> and the
/// request's route values: typed route parameters and <see cref="EndpointInfo"/> (route template,
/// controller/action names, parameter sources derived from model binding).
/// </summary>
internal static class RouteSchemaExtractor
{
    /// <summary>Extracts a typed <see cref="RouteParameter"/> list from the request's route values; null
    /// values are skipped and each parameter's CLR type is inferred from the route pattern.</summary>
    public static IReadOnlyList<RouteParameter> ExtractRouteParameters(HttpRequest request, Endpoint? endpoint)
    {
        if (request.RouteValues.Count == 0)
        {
            return [];
        }

        var pattern = (endpoint as RouteEndpoint)?.RoutePattern;
        var result = new List<RouteParameter>(request.RouteValues.Count);

        foreach (var (name, value) in request.RouteValues)
        {
            if (value is null || name == "action" || name == "controller")
            {
                continue;
            }

            var clrType = InferRouteParamClrType(pattern, name);
            result.Add(new RouteParameter(name, value.ToString() ?? string.Empty, clrType));
        }

        return result;
    }

    /// <summary>Infers a route parameter's CLR type from the constraint policies in the route pattern;
    /// unconstrained parameters are treated as <c>string</c> until model binding runs.</summary>
    private static string InferRouteParamClrType(RoutePattern? pattern, string name)
    {
        var parameter = pattern?.GetParameter(name);
        if (parameter is not null)
        {
            foreach (var policy in parameter.ParameterPolicies)
            {
                if (policy.Content is null) continue;
                var clr = ConstraintToClrType(policy.Content);
                if (clr is not null)
                {
                    return clr;
                }
            }
        }

        return "string";
    }

    /// <summary>Maps a route constraint name (<c>int</c>, <c>guid</c>, <c>datetime</c>, etc.) to the
    /// corresponding CLR type name; returns null for a constraint that cannot be mapped.</summary>
    private static string? ConstraintToClrType(string constraint) => constraint switch
    {
        "int" => "int",
        "long" => "long",
        "guid" => "Guid",
        "bool" => "bool",
        "decimal" => "decimal",
        "double" => "double",
        "float" => "float",
        "datetime" => "DateTime",
        "minlength" or "maxlength" or "length" or "alpha" or "regex" => "string",
        _ => null,
    };

    /// <summary>Builds an <see cref="EndpointInfo"/> from a resolved <see cref="Endpoint"/> containing the
    /// route template, endpoint/controller/action names, and the typed parameter schema derived from model
    /// binding; when there is no endpoint, uses the raw request path as the template.</summary>
    public static EndpointInfo BuildEndpointInfo(Endpoint? endpoint, HttpContext context)
    {
        if (endpoint is null)
        {
            return new EndpointInfo { RouteTemplate = context.Request.Path.Value ?? string.Empty };
        }

        var routePattern = (endpoint as RouteEndpoint)?.RoutePattern;
        var controllerDescriptor = endpoint.Metadata.GetMetadata<ControllerActionDescriptor>();
        var endpointNameMetadata = endpoint.Metadata.GetMetadata<EndpointNameMetadata>();
        var methodInfo = endpoint.Metadata.GetMetadata<System.Reflection.MethodInfo>();

        var routeParamNames = routePattern?.Parameters.Select(p => p.Name).ToHashSet(StringComparer.OrdinalIgnoreCase)
                              ?? new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        var parameterTypes = new List<BoundParameterType>();
        if (controllerDescriptor is not null)
        {
            foreach (var p in controllerDescriptor.Parameters)
            {
                var source = ClassifyParameterSource(p.BindingInfo?.BindingSource?.Id, p.Name, routeParamNames, p.ParameterType);
                parameterTypes.Add(new BoundParameterType(p.Name, p.ParameterType.Name, source));
            }
        }
        else if (methodInfo is not null)
        {
            foreach (var p in methodInfo.GetParameters())
            {
                if (p.Name is null) continue;
                var source = ClassifyParameterSource(null, p.Name, routeParamNames, p.ParameterType);
                parameterTypes.Add(new BoundParameterType(p.Name, p.ParameterType.Name, source));
            }
        }

        return new EndpointInfo
        {
            RouteTemplate = routePattern?.RawText ?? context.Request.Path.Value ?? string.Empty,
            EndpointName = endpointNameMetadata?.EndpointName,
            DisplayName = endpoint.DisplayName,
            ControllerName = controllerDescriptor?.ControllerName,
            ActionName = controllerDescriptor?.ActionName,
            ParameterTypes = parameterTypes,
            ResponseClrTypeName = null,
        };
    }

    /// <summary>Determines a parameter's binding source (<see cref="ParameterSource"/>). When the MVC
    /// binding source is known, it is mapped against the actual <see cref="BindingSource"/> constants
    /// (compiler-verified); when unknown (Minimal API), a heuristic is applied: a name matching a route →
    /// Route, a simple/primitive type → Query, otherwise Body, assuming an implicit <c>[FromBody]</c>.</summary>
    private static ParameterSource ClassifyParameterSource(string? mvcBindingSourceId, string name, HashSet<string> routeParamNames, Type clrType)
    {
        if (mvcBindingSourceId is not null)
        {
            return mvcBindingSourceId switch
            {
                var id when id == BindingSource.Path.Id => ParameterSource.Route,
                var id when id == BindingSource.Query.Id => ParameterSource.Query,
                var id when id == BindingSource.Body.Id => ParameterSource.Body,
                var id when id == BindingSource.Header.Id => ParameterSource.Header,
                var id when id == BindingSource.Form.Id || id == BindingSource.FormFile.Id => ParameterSource.Form,
                _ => routeParamNames.Contains(name) ? ParameterSource.Route : ParameterSource.Query,
            };
        }

        if (routeParamNames.Contains(name))
        {
            return ParameterSource.Route;
        }

        var underlying = Nullable.GetUnderlyingType(clrType) ?? clrType;
        var isSimple = underlying.IsPrimitive || underlying.IsEnum
            || underlying == typeof(string) || underlying == typeof(Guid)
            || underlying == typeof(decimal) || underlying == typeof(DateTime)
            || underlying == typeof(DateTimeOffset);

        return isSimple ? ParameterSource.Query : ParameterSource.Body;
    }
}
