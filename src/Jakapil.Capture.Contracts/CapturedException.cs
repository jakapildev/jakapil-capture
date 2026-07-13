namespace Jakapil.Capture.Contracts;

/// <summary>Wire contract of a captured server-side exception.
/// The wire counterpart of <c>Jakapil.Core.Capture.CapturedException</c>.</summary>
public sealed record CapturedException
{
    /// <summary>The full type name of the exception.</summary>
    public required string Type { get; init; }

    /// <summary>The exception's message.</summary>
    public required string Message { get; init; }

    /// <summary>Offload reference to external storage for the stack trace.</summary>
    public string? StackTraceRef { get; init; }
}
