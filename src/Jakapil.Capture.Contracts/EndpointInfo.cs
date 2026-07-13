namespace Jakapil.Capture.Contracts;

/// <summary>
/// Route template and endpoint identity (wire contract) — the core of downstream deduplication and
/// parameterization. The wire counterpart of <c>Jakapil.Core.Capture.EndpointInfo</c>.
/// </summary>
public sealed record EndpointInfo
{
    /// <summary>The route template (e.g. <c>/api/products/{id:int}</c>).</summary>
    public required string RouteTemplate { get; init; }

    /// <summary>The name of the endpoint (e.g. <c>WithName("GetProductById")</c>).</summary>
    public string? EndpointName { get; init; }

    /// <summary>The display name of the endpoint.</summary>
    public string? DisplayName { get; init; }

    /// <summary>The controller name (on MVC endpoints).</summary>
    public string? ControllerName { get; init; }

    /// <summary>The action name (on MVC endpoints).</summary>
    public string? ActionName { get; init; }

    /// <summary>The typed parameter schema derived from model binding; feeds the downstream static noise analysis.</summary>
    public IReadOnlyList<BoundParameterType> ParameterTypes { get; init; } = [];

    /// <summary>The CLR type name of the return DTO, if known.</summary>
    public string? ResponseClrTypeName { get; init; }
}

/// <summary>The name, value, and CLR type of a route parameter.</summary>
public sealed record RouteParameter(string Name, string Value, string ClrType);

/// <summary>The name, CLR type, and binding source of a parameter derived from model binding.</summary>
public sealed record BoundParameterType(string Name, string ClrType, ParameterSource Source);

/// <summary>The source a parameter is bound from: route, query, body, header, or form.</summary>
public enum ParameterSource { Route, Query, Body, Header, Form }
