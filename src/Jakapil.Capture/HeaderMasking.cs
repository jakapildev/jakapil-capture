using Microsoft.AspNetCore.Http;

namespace Jakapil.Capture;

/// <summary>
/// Header masking at capture time: sensitive headers are masked at record time in the form <c>••••+last4</c>
/// (the first of two masking layers).
/// </summary>
/// <remarks>
/// Sensitive header <b>values</b> are altered before the interaction leaves the customer's process; the raw
/// secret never reaches the collector. The set of sensitive header names is driven by
/// <see cref="JakapilCaptureOptions.SensitiveHeaderNames"/> rather than hard-coded, so a host can extend it.
/// </remarks>
internal static class HeaderMasking
{
    private const string MaskPrefix = "••••••••";
    private const string BearerScheme = "Bearer ";

    /// <summary>Projects an <see cref="IHeaderDictionary"/> into a plain string mapping; masks the value of
    /// every header whose name matches <paramref name="sensitiveNames"/> (case-insensitive).</summary>
    public static IReadOnlyDictionary<string, string> MaskHeaders(IHeaderDictionary headers, string[] sensitiveNames)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (key, value) in headers)
        {
            var isSensitive = Array.Exists(sensitiveNames, n => string.Equals(n, key, StringComparison.OrdinalIgnoreCase));
            result[key] = isSensitive ? MaskValue(value.ToString()) : value.ToString();
        }

        return result;
    }

    /// <summary>
    /// Masks a single header value.
    /// </summary>
    /// <remarks>
    /// The <c>Bearer </c> scheme prefix (case-insensitive) is preserved as-is, so the authentication scheme
    /// stays visible. The remainder (or, for a non-Bearer header, the entire value) becomes
    /// <c>MaskPrefix</c> + the last 4 characters of the raw value (or just the prefix if the value is 4
    /// characters or shorter). The raw value never appears in the result apart from this trailing 4-character piece.
    /// </remarks>
    public static string MaskValue(string value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return MaskPrefix;
        }

        if (value.StartsWith(BearerScheme, StringComparison.OrdinalIgnoreCase))
        {
            var token = value[BearerScheme.Length..];
            return BearerScheme + MaskToken(token);
        }

        return MaskToken(value);
    }

    /// <summary>Masks a token with the fixed prefix + its last 4 characters; if the token is 4 characters
    /// or shorter, only the prefix is returned.</summary>
    private static string MaskToken(string token)
    {
        if (token.Length == 0)
        {
            return MaskPrefix;
        }

        var tail = token.Length <= 4 ? token : token[^4..];
        return MaskPrefix + tail;
    }
}
