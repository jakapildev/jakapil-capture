namespace Jakapil.Capture.Contracts;

/// <summary>
/// A captured request/response body (wire contract). Never silently corrupted: if it must be shortened,
/// it is cut at a JSON/UTF-8 boundary and marked with <see cref="Truncated"/> — never mid-character.
/// The wire counterpart of <c>Jakapil.Core.Capture.CapturedBody</c>.
/// </summary>
public sealed record CapturedBody
{
    /// <summary>The body text below the size limit; kept inline.</summary>
    public required string? Text { get; init; }

    /// <summary>Offload reference to external storage for bodies exceeding the limit.</summary>
    public string? BlobRef { get; init; }

    /// <summary>The raw byte size of the body.</summary>
    public required long ByteSize { get; init; }

    /// <summary>True when the body was truncated because it exceeded the size limit.</summary>
    public required bool Truncated { get; init; }

    /// <summary>The classified content kind of the body.</summary>
    public required BodyKind Kind { get; init; }
}

/// <summary>The content kind of a captured body: empty, JSON, form, text, or binary.</summary>
public enum BodyKind { Empty, Json, Form, Text, Binary }
