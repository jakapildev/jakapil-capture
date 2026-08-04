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

    /// <summary>ADR §5/§7: known PII field names → <see cref="FieldClass.SyntheticPii"/>. These are STRONG
    /// signals — the name alone is specific enough to a person that no surrounding context is needed (unlike
    /// <see cref="ContextSensitiveFieldNames"/> below). Deliberately does NOT include the generic <c>name</c>
    /// — see the context-sensitivity note on <see cref="ContextSensitiveFieldNames"/> for why it was moved out.</summary>
    public static readonly HashSet<string> PiiFieldNames = new(StringComparer.Ordinal)
    {
        "email", "phone", "phonenumber", "ssn", "tckn", "iban", "address", "dob", "birthdate", "dateofbirth",
        "fullname", "firstname", "lastname", "surname", "cardnumber", "creditcard", "cvv", "pan",
        "nationalid", "passport",
    };

    /// <summary>
    /// Field names that are too GENERIC to classify from the name alone — they need the enclosing object's own
    /// field name (<see cref="FieldClassifier.Classify"/>'s <c>parentFieldName</c> parameter) to decide whether
    /// they denote a person. Currently only <c>name</c>.
    /// </summary>
    /// <remarks>
    /// <para><b>Why this exists (field bug report, v1.2.0):</b> a captured eShop response
    /// <c>GET /api/catalog-types</c> — <c>{ "catalogTypes": [ { "name": "Mug" }, { "name": "T-Shirt" }, ... ] }</c>
    /// — had every <c>name</c> (a product-category label, not a person) rewritten to a synthetic person name
    /// ("Sage Blake", "Ash Park", ...) because the old rule treated bare <c>name</c> exactly like
    /// <c>fullName</c>/<c>firstName</c>. Scenarios generated from that capture then replayed against the live
    /// API and asserted the wrong (synthetic) literal on every run — a 100%-reproducible FALSE regression, not
    /// a real one. <c>name</c> is classified <see cref="FieldClass.SyntheticPii"/> ONLY when
    /// <see cref="FieldClassifier.Classify"/>'s <c>parentFieldName</c> — the field name of the object that
    /// directly contains it — normalizes to one of <see cref="PersonContextNames"/> (e.g. <c>$.customer.name</c>,
    /// <c>$.billingAddress.name</c>). With no parent (root-level <c>name</c>) or a non-person parent
    /// (<c>$.catalogTypes[].name</c>, <c>$.products[].name</c>) it falls through to the ordinary
    /// name/type/entropy rules — <see cref="FieldClass.SafeLiteral"/> for a short, non-free-text label — and the
    /// real value is sent, matching the eShop example above.</para>
    /// <para><b>Privacy trade-off — read before relying on this default.</b> This intentionally LOOSENS the
    /// default: a false positive (real category label classified as PII) becomes rarer, but so does the safety
    /// margin — a field literally called <c>name</c> that DOES hold a person's name, sitting under a parent
    /// object whose name isn't recognized as person-like (a custom/unusual schema), will now be sent as
    /// plaintext instead of being synthesized. The strong-signal names in <see cref="PiiFieldNames"/>
    /// (<c>fullName</c>/<c>firstName</c>/<c>lastName</c>/<c>surname</c>) are NOT affected by this change and
    /// remain unconditionally <see cref="FieldClass.SyntheticPii"/> in every context. If a customer's schema
    /// uses bare <c>name</c> for a person field in a context this heuristic does not recognize, the documented
    /// escape hatch is <see cref="AnonymizationOptions.FieldPolicy"/> (ADR-0002 §5 priority #1, always wins):
    /// map that field name to <see cref="FieldClass.SyntheticPii"/> explicitly.</para>
    /// <para><b>Why not generalize to other generic names (e.g. <c>title</c>):</b> deliberately out of scope —
    /// the reported failure is specific to <c>name</c>, and a name like <c>title</c> is ambiguous in the
    /// opposite direction just as often (job title, book title, page title) without a reported false-positive
    /// to justify the added rule. Extend this set only with a concrete, documented case, not speculatively.</para>
    /// </remarks>
    public static readonly HashSet<string> ContextSensitiveFieldNames = new(StringComparer.Ordinal) { "name" };

    /// <summary>
    /// Parent-object field-name WORDS that make a <see cref="ContextSensitiveFieldNames"/> field (currently just
    /// <c>name</c>) resolve to <see cref="FieldClass.SyntheticPii"/> instead of falling through to the ordinary
    /// rules. Checked via <see cref="HasPersonContext"/> against each WORD of the JSON object that directly
    /// contains the field (see that method for why word-splitting, not whole-name matching, is required) — e.g.
    /// for <c>$.customer.name</c> the parent word is <c>customer</c> (match); for <c>$.billingAddress.name</c>
    /// the parent words are <c>billing</c>/<c>address</c> (match, either is enough); for
    /// <c>$.catalogTypes[].name</c> the parent words are <c>catalog</c>/<c>types</c> (no match).
    /// </summary>
    public static readonly HashSet<string> PersonContextNames = new(StringComparer.Ordinal)
    {
        "user", "customer", "person", "contact", "member", "employee", "account", "buyer", "seller",
        "recipient", "sender", "owner", "author", "patient", "client", "guest", "subscriber", "profile",
        "billing", "shipping", "address",
    };

    /// <summary>Returns true if any WORD of <paramref name="parentFieldName"/> (split the same way
    /// <see cref="ExtractIdentifierRole"/> splits camelCase/PascalCase/snake_case/kebab-case names) — or a
    /// <see cref="SingularCandidates"/> of that word — is in <see cref="PersonContextNames"/>. Word-splitting —
    /// rather than matching the whole normalized name — is required for compound parent names like
    /// <c>billingAddress</c>/<c>shippingAddress</c> (splits to <c>billing</c>/<c>address</c> and
    /// <c>shipping</c>/<c>address</c>): <see cref="Normalize"/> alone would concatenate these into
    /// <c>billingaddress</c>/<c>shippingaddress</c>, neither of which is itself listed. Singularization is
    /// required for the single most common REST shape of all — a plural collection endpoint
    /// (<c>$.users[].name</c>, <c>$.customers[].name</c>, <c>$.employees[].name</c>): without it, the parent
    /// word is <c>users</c>/<c>customers</c>/<c>employees</c>, none of which is literally in
    /// <see cref="PersonContextNames"/>, and a real person's name would be sent as plaintext
    /// <see cref="FieldClass.SafeLiteral"/> — see <see cref="SingularCandidates"/> for why this must
    /// deliberately over-match rather than under-match.</summary>
    public static bool HasPersonContext(string? parentFieldName)
    {
        if (string.IsNullOrEmpty(parentFieldName))
        {
            return false;
        }

        foreach (var word in SplitWords(parentFieldName))
        {
            var normalizedWord = Normalize(word);
            if (normalizedWord.Length == 0)
            {
                continue;
            }

            foreach (var candidate in SingularCandidates(normalizedWord))
            {
                if (PersonContextNames.Contains(candidate))
                {
                    return true;
                }
            }
        }

        return false;
    }

    /// <summary>
    /// Yields <paramref name="normalizedWord"/> itself, plus every simple suffix-stripped singular form worth
    /// trying against <see cref="PersonContextNames"/> — <c>users</c> → <c>user</c>, <c>employees</c> →
    /// <c>employee</c>, <c>companies</c> → <c>company</c>, <c>addresses</c> → <c>address</c>. Intentionally
    /// crude: three fixed suffix rules, no inflection library, no exceptions dictionary, no IO (the classifier
    /// stays pure) — tries plain trailing-<c>s</c> stripping, <c>ies</c>→<c>y</c>, and <c>es</c>→<c>""</c>, and
    /// lets the caller's set-membership check decide which (if any) candidate is real; a wrong candidate that
    /// matches nothing in <see cref="PersonContextNames"/> is simply ignored.
    /// </summary>
    /// <remarks>
    /// <b>Deliberately biased toward OVER-matching, never under-matching — do not "optimize" this later.</b>
    /// The two failure directions are NOT symmetric:
    /// <list type="bullet">
    /// <item>A false MATCH (some unrelated plural word happens to singularize into a listed person-context
    /// word) merely anonymizes a field that did not strictly need it — a correctness annoyance, fully
    /// recoverable via <see cref="AnonymizationOptions.FieldPolicy"/>.</item>
    /// <item>A false MISS (a real plural person collection, e.g. <c>users</c>, not recognized) sends REAL PII to
    /// the collector in PLAINTEXT — unrecoverable, the value has already left the customer's process by the
    /// time anyone could notice.</item>
    /// </list>
    /// When in doubt, or when adding a new suffix rule, this method must widen matching, never narrow it.
    /// </remarks>
    private static IEnumerable<string> SingularCandidates(string normalizedWord)
    {
        yield return normalizedWord;

        // "companies" -> "company", "addresses" via the `es` rule below (this one alone would wrongly yield
        // "companie"; the `es` rule catches short forms the `ies` rule does not apply to).
        if (normalizedWord.Length > 4 && normalizedWord.EndsWith("ies", StringComparison.Ordinal))
        {
            yield return string.Concat(normalizedWord.AsSpan(0, normalizedWord.Length - 3), "y");
        }

        // "addresses" -> "address", "employees" (also covered by the plain -s rule below, tried anyway — cheap
        // and harmless since the caller only cares whether ANY candidate matches).
        if (normalizedWord.Length > 4 && normalizedWord.EndsWith("es", StringComparison.Ordinal))
        {
            yield return normalizedWord[..^2];
        }

        // "users" -> "user", "customers" -> "customer", "employees" -> "employee". The general case; length
        // guard avoids reducing very short words (e.g. a 3-letter word) to something meaningless.
        if (normalizedWord.Length > 3 && normalizedWord.EndsWith('s'))
        {
            yield return normalizedWord[..^1];
        }
    }

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

    /// <summary>
    /// GIZLILIK-2/G-1-1 (v1.3.1): pagination/counter names that are <see cref="FieldClass.SafeLiteral"/> ONLY
    /// in a TRANSPORT position (a route/query/header value — see
    /// <see cref="Anonymizer.TransformTransportValue"/>'s consumption of this set), never in a JSON body.
    /// </summary>
    /// <remarks>
    /// <para><b>The bug this fixes:</b> a request's <c>?PageSize=10&amp;PageIndex=0</c> anonymized to something
    /// like <c>?PageSize=35&amp;PageIndex=1</c> — a different, unrelated number — because neither name is in
    /// <see cref="SafeLiteralFieldNames"/> (only <c>page</c>/<c>limit</c> are), so both fell to the INV-A3
    /// unknown-field fail-safe (<see cref="FieldClass.SyntheticPii"/>, type-preserving since v1.2.0 but still a
    /// DIFFERENT number). Corrupting a pagination parameter's value changes the request's meaning, not just its
    /// identity, so the resulting scenario keeps asserting against the wrong page forever.</para>
    /// <para><b>Deliberately NOT merged into <see cref="SafeLiteralFieldNames"/>:</b> that set is consulted by
    /// <see cref="FieldClassifier.Classify"/>, which has no notion of "transport vs JSON body" — merging would
    /// also make a body leaf like <c>{"pageSize": "10"}</c> SafeLiteral, which is out of scope here (no reported
    /// defect for the body position, and body free-text fields like <c>note</c>/<c>description</c> must keep
    /// synthesizing regardless of what a sibling counter field is named). <see cref="Anonymizer.TransformTransportValue"/>
    /// consumes this set directly, gated by <see cref="SyntheticPiiGenerator.DetectTransportShape"/> resolving to
    /// Integer/Decimal — a name match against a non-numeric value (e.g. <c>?pageSize=ahmet@x.com</c>) does NOT
    /// take the exception, so a name/value mismatch can never leak free text through this path. No digit-count
    /// limit is applied — a legitimate <c>offset=1000000</c> must still pass unchanged.</para>
    /// <para><b>Deliberately excludes <c>sort</c>/<c>order</c>/<c>orderBy</c>/<c>direction</c>/<c>asc</c>/<c>desc</c>:</b>
    /// no concrete failure has been reported for these, and <c>order</c> in particular can hold a business
    /// reference (e.g. <c>"ORD-2024-000123"</c>) rather than a sort direction — widening this set to cover them
    /// is deliberately deferred until a real case justifies it (same "extend only with a concrete, documented
    /// case" discipline as <see cref="ContextSensitiveFieldNames"/>).</para>
    /// </remarks>
    public static readonly HashSet<string> TransportCounterFieldNames = new(StringComparer.Ordinal)
    {
        "pagesize", "pageindex", "pagenumber", "perpage", "offset", "skip", "take", "top",
    };

    /// <summary>The three semantic roles ADR §6.1/§9 recognizes for flow identifiers.</summary>
    private static readonly HashSet<string> IdentifierRoleWords = new(StringComparer.Ordinal) { "id", "ref", "key" };

    /// <summary>
    /// ADR-0003 §5 revision (v1.2.0, <c>RunCredential</c>): the semantic-kind allowlist for values a signed-replay
    /// response may pass through LIVE instead of masking, because the TARGET produced them during this run and the
    /// Runner must chain them into the next step's request — the same structural reason <see cref="FieldClass.FlowFingerprint"/>
    /// already passes through live (<c>Anonymizer.ApplyClass</c>'s <c>isReplayMasking</c> path). Deliberately does
    /// NOT include <c>password</c> or any other <see cref="SecretFieldNames"/> entry outside this exact list —
    /// those are INPUT secrets the caller supplied, not artifacts the target issued, and must stay tombstoned even
    /// in a replay response (see <see cref="ExtractRunCredentialKind"/> remarks for why <c>password</c> can never
    /// match here by construction, not by an extra exclusion check).
    /// </summary>
    private static readonly HashSet<string> RunCredentialKindWords = new(StringComparer.Ordinal)
    {
        "token", "session", "cookie", "csrf", "cursor",
    };

    /// <summary>
    /// Extracts the RunCredential semantic kind ("token"/"session"/"cookie"/"csrf"/"cursor") from a field name's
    /// LAST camelCase/PascalCase/snake_case/kebab-case word, or null if the name does not end in one of those
    /// words — mirrors <see cref="ExtractIdentifierRole"/> exactly (same <see cref="SplitWords"/> word-splitting,
    /// last word only), so the same false-positive bound applies: a whole-word match on the TRAILING word only,
    /// never a substring/prefix match (<c>tokenizer</c> does not match "token"; <c>authToken</c>/<c>sessionId</c>-
    /// no wait, <c>sessionId</c>'s last word is "Id" not "session" — see the worked examples below).
    /// </summary>
    /// <remarks>
    /// <para><b>Why <c>password</c> can never match:</b> not by an exclusion list, but structurally — "password"
    /// is not, and will never be added to, <see cref="RunCredentialKindWords"/>. A compound name like
    /// <c>passwordResetToken</c> DOES match (last word "Token") — correctly so: that field holds a token the
    /// target issued during this run (a run artifact), not the password value itself. This is the intended
    /// behavior, not a gap: the decision boundary is "did the TARGET produce this during the run" (token: yes),
    /// never "does the name contain the substring 'password'".</para>
    /// <para><b>Worked examples:</b> <c>token</c> → "token" (whole name); <c>authToken</c>/<c>sessionToken</c>/
    /// <c>csrfToken</c> → "token" (trailing word); <c>sessionId</c> → null (trailing word is "id", the
    /// FlowFingerprint role, not a RunCredential kind — already handled by the existing FlowFingerprint
    /// passthrough); <c>pageCursor</c>/<c>nextCursor</c> → "cursor"; <c>xsrfCookie</c> → "cookie" (splits to
    /// ["xsrf","Cookie"], trailing word matches); <c>tokenizer</c> → null (one lowercase word "tokenizer", not
    /// equal to "token" — whole-word match only, never substring/prefix).</para>
    /// </remarks>
    public static string? ExtractRunCredentialKind(string fieldName)
    {
        var words = SplitWords(fieldName);
        if (words.Count == 0)
        {
            return null;
        }

        var last = words[^1].ToLowerInvariant();
        return RunCredentialKindWords.Contains(last) ? last : null;
    }

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
