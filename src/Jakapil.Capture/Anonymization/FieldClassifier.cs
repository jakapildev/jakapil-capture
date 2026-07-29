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
/// and (context-independent, strong-signal) PII names → <see cref="FieldClass.SyntheticPii"/>; a small set of
/// GENERIC, context-sensitive names (<see cref="FieldNameRules.ContextSensitiveFieldNames"/>, currently just
/// <c>name</c>) → <see cref="FieldClass.SyntheticPii"/> ONLY if the enclosing object's own field name suggests
/// a person (<see cref="FieldNameRules.PersonContextNames"/>), otherwise <see cref="FieldClass.SafeLiteral"/>
/// directly (v1.2.0 fix — see that set's remarks for the false-positive this eliminates and the privacy
/// trade-off it accepts); the small SafeLiteral allowlist (enum-like/measure names) →
/// <see cref="FieldClass.SafeLiteral"/>.</item>
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
    /// <param name="fieldName">The leaf's own field name (route/query/header name, or JSON property name).</param>
    /// <param name="kind">The leaf's shape — see <see cref="LeafValueKind"/>.</param>
    /// <param name="rawText">The raw captured value, used only by the entropy-shape fallback (step 4).</param>
    /// <param name="fieldPolicy"><see cref="AnonymizationOptions.FieldPolicy"/> — always wins (step 1).</param>
    /// <param name="parentFieldName">The field name of the JSON object that DIRECTLY contains this leaf (e.g.
    /// for <c>$.customer.name</c>, this is <c>"customer"</c>), or null at the document root or for a
    /// route/query/header value (which has no JSON container). Used ONLY by the
    /// <see cref="FieldNameRules.ContextSensitiveFieldNames"/> check — every other rule ignores it. See
    /// <see cref="FieldNameRules.ContextSensitiveFieldNames"/> for why a generic name like <c>name</c> needs
    /// this and the privacy trade-off it documents.</param>
    public static FieldClass Classify(
        string? fieldName, LeafValueKind kind, string? rawText, IReadOnlyDictionary<string, FieldClass>? fieldPolicy,
        string? parentFieldName = null)
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

            // Generic names (currently only "name") only mean PII when the enclosing object's own field name
            // suggests a person; with no parent or a non-person parent they resolve directly to SafeLiteral —
            // a deliberate exception to the INV-A3 fail-safe fallback below (which would otherwise synthesize
            // any unrecognized string), because this is no longer an UNRECOGNIZED name, it is a name explicitly
            // evaluated and found not to indicate PII (see FieldNameRules.ContextSensitiveFieldNames remarks
            // for the bug this fixes and the resulting privacy trade-off).
            if (FieldNameRules.ContextSensitiveFieldNames.Contains(normalized))
            {
                return FieldNameRules.HasPersonContext(parentFieldName) ? FieldClass.SyntheticPii : FieldClass.SafeLiteral;
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
