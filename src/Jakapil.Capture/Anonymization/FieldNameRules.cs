using System.Text;

namespace Jakapil.Capture.Anonymization;

/// <summary>
/// Shared, pure name/shape rules used by both <see cref="FieldClassifier"/> (which class a field falls into)
/// and <see cref="SyntheticPiiGenerator"/> (which synthetic generator applies) — ADR-0002 §5 "known field
/// rules" plus the §6.1 semantic-role extraction that makes cross-field correlation work
/// (<c>customerId</c> and a response's plain <c>id</c> must resolve to the SAME semantic role, "id", or their
/// digests would never match — see <see cref="ExtractIdentifierRole"/>).
/// </summary>
/// <remarks>
/// These lists are deliberately small and curated, exactly like the server-side
/// <c>Jakapil.Api.Ingest.IngestSecretPatterns</c> they mirror in spirit: they are NOT exhaustive (ADR §10 — no
/// server-side rule can be), a customer extends/overrides them via <see cref="AnonymizationOptions.FieldPolicy"/>.
/// </remarks>
internal static class FieldNameRules
{
    /// <summary>ADR §2/§8: secret field names → <see cref="FieldClass.SecretTombstone"/> (never fingerprinted —
    /// low entropy, dictionary-attackable if the key leaks).</summary>
    public static readonly HashSet<string> SecretFieldNames = new(StringComparer.Ordinal)
    {
        "password", "token", "secret", "apikey", "authorization", "cookie",
    };

    /// <summary>ADR §5/§7: known PII field names → <see cref="FieldClass.SyntheticPii"/>.</summary>
    public static readonly HashSet<string> PiiFieldNames = new(StringComparer.Ordinal)
    {
        "email", "phone", "phonenumber", "ssn", "tckn", "iban", "address", "dob", "birthdate", "dateofbirth",
        "fullname", "firstname", "lastname", "surname", "name", "cardnumber", "creditcard", "cvv", "pan",
        "nationalid", "passport",
    };

    /// <summary>ADR §5 (fail-safe, INV-A3): free-text fields are NOT SafeLiteral by default — the server
    /// cannot distinguish <c>"currency": "TRY"</c> from <c>"note": "met with John Smith"</c>, so free text
    /// always synthesizes.</summary>
    public static readonly HashSet<string> FreeTextFieldNames = new(StringComparer.Ordinal)
    {
        "description", "note", "message", "comment",
    };

    /// <summary>ADR §2/§5 worked examples of the low-cardinality/measure allowlist:
    /// <c>currency</c>/<c>quantity</c> are given verbatim; <c>status</c>/<c>type</c>/<c>page</c>/<c>limit</c>
    /// are the same enum-like/counter shape. This list is intentionally small — see the report's open question
    /// about whether it should grow (e.g. <c>count</c>, <c>pageSize</c>, <c>offset</c>).</summary>
    public static readonly HashSet<string> SafeLiteralFieldNames = new(StringComparer.Ordinal)
    {
        "status", "currency", "type", "quantity", "page", "limit",
    };

    /// <summary>The three semantic roles ADR §6.1/§9 recognizes for flow identifiers.</summary>
    private static readonly HashSet<string> IdentifierRoleWords = new(StringComparer.Ordinal) { "id", "ref", "key" };

    /// <summary>Reduces a raw name to the ASCII-letter/digit-only, lowercase token the server-side
    /// <c>ValueEnvelope</c> grammar requires for <c>semanticKind</c>/tombstone <c>kind</c>
    /// (<c>char.IsAsciiLetterOrDigit</c>, non-empty); separators/non-ASCII characters are dropped. Returns
    /// empty when nothing survives (e.g. an all-Unicode/emoji field name) — callers decide the fallback.</summary>
    public static string Normalize(string name)
    {
        Span<char> buffer = name.Length <= 128 ? stackalloc char[name.Length] : new char[name.Length];
        var count = 0;
        foreach (var c in name)
        {
            if (char.IsAsciiLetterOrDigit(c))
            {
                buffer[count++] = char.ToLowerInvariant(c);
            }
        }

        return count == 0 ? string.Empty : new string(buffer[..count]);
    }

    /// <summary>
    /// Extracts the canonical semantic role ("id"/"ref"/"key") from a field name's LAST camelCase/PascalCase/
    /// snake_case/kebab-case word, or null if the name does not end in one of those roles.
    /// </summary>
    /// <remarks>
    /// This is the mechanism behind ADR §9's worked example: a request's <c>customerId</c> and a prior
    /// response's plain <c>id</c> field must produce the SAME digest for the correlation edge to exist, which
    /// requires the SAME <c>semanticKind</c> input to the HMAC — so both resolve to the role "id", discarding
    /// the "customer"/"product"/etc. qualifier. Word-splitting (rather than a raw suffix check) exists
    /// specifically to avoid false positives like "valid" (ends in the letters "id" but is one lowercase word,
    /// not a camelCase-separated "...Id" suffix) or "grid" — see <c>FieldClassifierTests</c>.
    /// A simple plural is also recognized (<c>productIds</c> → "id"), since array-of-identifiers fields are common.
    /// </remarks>
    public static string? ExtractIdentifierRole(string fieldName)
    {
        var words = SplitWords(fieldName);
        if (words.Count == 0)
        {
            return null;
        }

        var last = words[^1].ToLowerInvariant();
        if (IdentifierRoleWords.Contains(last))
        {
            return last;
        }

        if (last.Length > 1 && last[^1] == 's')
        {
            var singular = last[..^1];
            if (IdentifierRoleWords.Contains(singular))
            {
                return singular;
            }
        }

        return null;
    }

    /// <summary>Conservative shape check for "this looks like an opaque identifier" — used only as the LAST
    /// resort fallback for a value with no usable field name (ADR §5 ad-hoc entropy heuristic): a GUID, an
    /// all-digit token of non-trivial length, or a long token drawn from an alphanumeric (opaque-token-shaped)
    /// alphabet.</summary>
    public static bool LooksLikeIdentifierShape(string raw)
    {
        if (raw.Length == 0)
        {
            return false;
        }

        if (Guid.TryParse(raw, out _))
        {
            return true;
        }

        var allDigits = true;
        var allAlnum = true;
        foreach (var c in raw)
        {
            if (!char.IsAsciiDigit(c))
            {
                allDigits = false;
            }

            if (!char.IsAsciiLetterOrDigit(c))
            {
                allAlnum = false;
                break;
            }
        }

        if (allDigits && raw.Length >= 5)
        {
            return true;
        }

        return allAlnum && raw.Length >= 16;
    }

    /// <summary>Splits a name into words at non-alphanumeric separators AND at lower/digit→upper camelCase
    /// boundaries (e.g. <c>customerId</c> → [<c>customer</c>, <c>Id</c>]; <c>product_id</c> → [<c>product</c>,
    /// <c>id</c>]; <c>valid</c> → [<c>valid</c>] — a single word, since it has no separator or case boundary).</summary>
    private static List<string> SplitWords(string name)
    {
        var words = new List<string>();
        var current = new StringBuilder();

        foreach (var c in name)
        {
            if (!char.IsLetterOrDigit(c))
            {
                if (current.Length > 0)
                {
                    words.Add(current.ToString());
                    current.Clear();
                }

                continue;
            }

            if (current.Length > 0 && char.IsUpper(c) && (char.IsLower(current[^1]) || char.IsDigit(current[^1])))
            {
                words.Add(current.ToString());
                current.Clear();
            }

            current.Append(c);
        }

        if (current.Length > 0)
        {
            words.Add(current.ToString());
        }

        return words;
    }
}
