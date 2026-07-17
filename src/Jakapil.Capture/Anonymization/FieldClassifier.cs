namespace Jakapil.Capture.Anonymization;

/// <summary>The shape of a JSON leaf being classified, without depending on <see cref="System.Text.Json.JsonValueKind"/>
/// directly so this type is reusable for route/query/header values too (which are always plain strings).</summary>
internal enum LeafValueKind
{
    /// <summary>A JSON string leaf, or a route/query/header value (always textual).</summary>
    String,

    /// <summary>A JSON number leaf.</summary>
    Number,

    /// <summary>A JSON <c>true</c>/<c>false</c>/<c>null</c> leaf — never ambiguous, always
    /// <see cref="FieldClass.SafeLiteral"/> (ADR §2/§5: booleans are the given enum-like example; null carries
    /// no information to leak).</summary>
    BoolOrNull,
}

/// <summary>
/// Classifies a single (field name, value) leaf into a <see cref="FieldClass"/>, following the ADR-0002 §5
/// priority order — OpenAPI metadata (priority #2) is skipped entirely: the SDK has no access to the API's
/// OpenAPI spec at capture time, only Core does (server-side, Phase 15e). The four steps applied here are:
/// </summary>
/// <remarks>
/// <list type="number">
/// <item><b>Customer policy</b> (<see cref="AnonymizationOptions.FieldPolicy"/>) — always wins.</item>
/// <item><i>(OpenAPI metadata — not available in the SDK; skipped, see class remarks.)</i></item>
/// <item><b>Known field-name rules</b>: secret names → <see cref="FieldClass.SecretTombstone"/>; free-text
/// and PII names → <see cref="FieldClass.SyntheticPii"/>; the small SafeLiteral allowlist (enum-like/measure
/// names) → <see cref="FieldClass.SafeLiteral"/>.</item>
/// <item><b>Name/type/entropy fallback (last resort)</b>: an <c>*Id</c>/<c>*Ref</c>/<c>*Key</c>-suffixed name
/// → <see cref="FieldClass.FlowFingerprint"/>; otherwise INV-A3 (fail-safe) applies — an unclassified JSON
/// number defaults to <see cref="FieldClass.SafeLiteral"/> (a bare measure has no PII shape), an unclassified
/// string that LOOKS like an opaque identifier (GUID/long numeric/opaque token) becomes
/// <see cref="FieldClass.FlowFingerprint"/>, and anything else unclassified becomes
/// <see cref="FieldClass.SyntheticPii"/> (never left as plaintext — "belirsiz kalan alan SafeLiteral olmaz").</item>
/// </list>
/// </remarks>
internal static class FieldClassifier
{
    public static FieldClass Classify(
        string? fieldName, LeafValueKind kind, string? rawText, IReadOnlyDictionary<string, FieldClass>? fieldPolicy)
    {
        // 1. Customer policy — highest priority, always wins.
        if (fieldName is not null && fieldPolicy is not null && fieldPolicy.TryGetValue(fieldName, out var overridden))
        {
            return overridden;
        }

        // Booleans/null are never ambiguous (ADR §2 lists boolean among the enum-like SafeLiteral examples).
        if (kind == LeafValueKind.BoolOrNull)
        {
            return FieldClass.SafeLiteral;
        }

        var normalized = fieldName is null ? string.Empty : FieldNameRules.Normalize(fieldName);
        var hasName = normalized.Length > 0;

        // 3. Known field-name rules.
        if (hasName)
        {
            if (FieldNameRules.SecretFieldNames.Contains(normalized))
            {
                return FieldClass.SecretTombstone;
            }

            if (FieldNameRules.FreeTextFieldNames.Contains(normalized) || FieldNameRules.PiiFieldNames.Contains(normalized))
            {
                return FieldClass.SyntheticPii;
            }

            if (FieldNameRules.SafeLiteralFieldNames.Contains(normalized))
            {
                return FieldClass.SafeLiteral;
            }
        }

        // 4. Name/type/entropy fallback (last resort).
        if (hasName && FieldNameRules.ExtractIdentifierRole(fieldName!) is not null)
        {
            return FieldClass.FlowFingerprint;
        }

        if (kind == LeafValueKind.Number)
        {
            // Fail-safe applies primarily to strings (ADR §5); a bare, unnamed number with no id/ref/key
            // suffix is treated as an ordinary measure (quantity/price/count shape), not personal data.
            return FieldClass.SafeLiteral;
        }

        if (!string.IsNullOrEmpty(rawText) && FieldNameRules.LooksLikeIdentifierShape(rawText))
        {
            return FieldClass.FlowFingerprint;
        }

        // INV-A3: an unclassified string never stays SafeLiteral.
        return FieldClass.SyntheticPii;
    }
}
