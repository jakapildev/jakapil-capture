using System.Buffers.Binary;
using System.Globalization;

namespace Jakapil.Capture.Anonymization;

/// <summary>
/// The shape a synthetic replacement must preserve (v1.2.0, type-preserving anonymization fix): a value that
/// was originally a JSON number or a numeric/boolean-looking transport token must synthesize to a replacement
/// that is STILL that shape — otherwise the target rejects the request (a numeric query parameter replaced by
/// an alphanumeric token fails model binding) or a schema assertion fails (a JSON number field replaced by a
/// JSON string). <see cref="Text"/> is the default/legacy shape — the existing named generators
/// (email/phone/name/free-text/generic) apply exactly as before.
/// </summary>
internal enum SyntheticValueShape
{
    /// <summary>Ordinary text — the named generators (email/phone/name/free-text/generic) apply.</summary>
    Text,

    /// <summary>A whole number — no fractional or exponent part in the original.</summary>
    Integer,

    /// <summary>A number with a fractional part in the original (JSON number with <c>.</c>/<c>e</c>/<c>E</c>,
    /// or transport text shaped like a decimal).</summary>
    Decimal,

    /// <summary>Transport text spelled exactly like a JSON boolean literal (<c>true</c>/<c>false</c>,
    /// case-insensitive on input). Never produced for a real JSON <c>true</c>/<c>false</c> leaf — those are
    /// never ambiguous (<see cref="FieldClassifier"/>) and are not walked through this generator at all.</summary>
    Boolean,
}

/// <summary>
/// Deterministic synthetic PII generator (ADR-0002 §7):
/// <c>synthetic = generator(kind, HMAC(key, scopeRef‖kind‖rawValue))</c>. Determinism is a
/// deliberate design choice (§7): the same production value always synthesizes to the same replacement, so
/// interaction dedup stays stable, <c>DynamicNoiseLearner</c> converges correctly, and request→response echo
/// relationships (e.g. a name submitted in a POST body reappearing in the 201 response) survive anonymization.
/// </summary>
internal static class SyntheticPiiGenerator
{
    private static readonly string[] FirstNameTokens =
        ["Alex", "Deniz", "Sam", "Kai", "Robin", "Ash", "Sage", "Jordan", "Taylor", "Morgan", "Yuki", "Noor"];

    private static readonly string[] LastNameTokens =
        ["Rivera", "Kaya", "Novak", "Singh", "Moon", "Park", "Reed", "Blake", "Stone", "Vance", "Demir", "Ito"];

    /// <summary>Generates the synthetic replacement for a classified <see cref="FieldClass.SyntheticPii"/>
    /// leaf. <paramref name="fieldName"/> selects which generator applies (email/phone/name/free-text/generic);
    /// null or an unrecognized name falls back to the generic token generator.</summary>
    /// <param name="shape">The shape (v1.2.0) the replacement MUST preserve. When not <see cref="SyntheticValueShape.Text"/>,
    /// this takes priority over every name-based generator below — a value that was itself numeric/boolean
    /// cannot correctly synthesize to a fake email/name/phone string (it would either corrupt the JSON's own
    /// number type, or fail the target's model binding on a query/route/header value), so the shape-preserving
    /// generator always wins for a non-text shape, regardless of field name.</param>
    public static string Generate(
        string? fieldName, string rawValue, ReadOnlySpan<byte> key, string scopeRef, string emailDomain,
        SyntheticValueShape shape = SyntheticValueShape.Text)
    {
        var normalized = fieldName is null ? string.Empty : FieldNameRules.Normalize(fieldName);
        var kindForSeed = normalized.Length == 0 ? "generic" : normalized;
        var seed = FingerprintGenerator.ComputeSyntheticSeed(key, scopeRef, kindForSeed, rawValue);

        switch (shape)
        {
            case SyntheticValueShape.Integer:
                return GenerateIntegerText(seed, rawValue);
            case SyntheticValueShape.Decimal:
                return GenerateDecimalText(seed, rawValue);
            case SyntheticValueShape.Boolean:
                return GenerateBooleanText(seed);
        }

        if (normalized == "email")
        {
            return GenerateEmail(seed, emailDomain);
        }

        if (normalized is "phone" or "phonenumber")
        {
            return GeneratePhone(seed);
        }

        if (normalized is "fullname" or "firstname" or "lastname" or "surname" or "name")
        {
            return GenerateName(seed);
        }

        if (normalized.Length > 0 && FieldNameRules.FreeTextFieldNames.Contains(normalized))
        {
            return GenerateFreeText(seed);
        }

        return GenerateGeneric(seed);
    }

    /// <summary>
    /// v1.2.0 (idempotent replay masking, WHY #2): recognizes a value that is ALREADY the deterministic output
    /// of one of the generators above, so the replay masking path (the only caller — see
    /// <see cref="FieldClass.SyntheticPii"/>'s replay disposition in <c>Anonymizer.ApplyClass</c>) can pass it
    /// through byte-identical instead of re-synthesizing it into a DIFFERENT synthetic value. Without this: the
    /// Runner sends a synthetic value from the corpus (e.g. a synthesized name) in a request, the target echoes
    /// it back in the response, and this SDK — seeing that echoed value as if it were fresh raw production data —
    /// synthesizes it AGAIN, seeded off the synthetic text itself rather than the original raw value, producing a
    /// SECOND, different synthetic value. Every echo-equality assertion built from the corpus then breaks
    /// structurally, even though nothing about the target's behavior changed.
    /// </summary>
    /// <remarks>
    /// <para><b>Scope and bound on false positives (never touches the capture path — this method is only ever
    /// called from replay masking):</b> recognition is deliberately NARROWED to the exact sub-generator this
    /// FIELD's own name would select (<see cref="Generate"/>'s same email/phone/name/free-text/generic dispatch)
    /// — never a blanket "does this look synthetic-ish" check against every pattern. This bounds the risk two
    /// ways: (1) a value is only ever compared against the ONE format its own field could plausibly have produced,
    /// not all five, cutting cross-generator false positives entirely; (2) each format's match is an EXACT,
    /// narrow shape (fixed literal prefix/suffix + fixed-length lowercase-hex run, or membership in a small closed
    /// name bank) — see each private helper below for the specific, quantified collision bound.</para>
    /// <para><b>Known, accepted limitation — <see cref="SyntheticValueShape.Integer"/>/<see cref="SyntheticValueShape.Decimal"/>/
    /// <see cref="SyntheticValueShape.Boolean"/> are NEVER recognized</b> (this method always returns false for
    /// them): a synthetic integer/decimal/boolean is, by construction, indistinguishable in FORMAT from an
    /// ordinary real one (there is no marker to detect) — recognizing "any number/boolean might already be
    /// synthetic" would defeat masking those fields entirely. An echoed numeric/boolean SyntheticPii value will
    /// therefore still re-synthesize to a different value on replay; this is a narrower, honestly-documented gap,
    /// not a silent one — numeric/boolean PII is already the rarer, fallback-only case (§ ADR-0002 §5 step 4).</para>
    /// </remarks>
    public static bool IsAlreadySynthetic(string? fieldName, string rawValue, string emailDomain, SyntheticValueShape shape)
    {
        if (shape != SyntheticValueShape.Text || string.IsNullOrEmpty(rawValue))
        {
            return false;
        }

        var normalized = fieldName is null ? string.Empty : FieldNameRules.Normalize(fieldName);

        if (normalized == "email")
        {
            return IsSyntheticEmailFormat(rawValue, emailDomain);
        }

        if (normalized is "phone" or "phonenumber")
        {
            return IsSyntheticPhoneFormat(rawValue);
        }

        if (normalized is "fullname" or "firstname" or "lastname" or "surname" or "name")
        {
            return IsSyntheticNameFormat(rawValue);
        }

        if (normalized.Length > 0 && FieldNameRules.FreeTextFieldNames.Contains(normalized))
        {
            return IsSyntheticFreeTextFormat(rawValue);
        }

        return IsSyntheticGenericFormat(rawValue);
    }

    /// <summary>Exact shape of <see cref="GenerateEmail"/>'s output: <c>user-</c> + 8 lowercase hex chars + `@` +
    /// the EXACT configured domain (not just "looks like an email"). Collision bound: for a real customer email
    /// to be misrecognized, it must independently match an 8-hex-digit local part under this literal prefix AND
    /// sit on the exact synthetic domain configured via <see cref="AnonymizationOptions.SyntheticEmailDomain"/> —
    /// roughly 1-in-4.3-billion (16^8) per candidate even restricted to that one domain, and organizations are
    /// advised (README) never to point that setting at a domain real customers also use.</summary>
    private static bool IsSyntheticEmailFormat(string rawValue, string domain)
    {
        const string prefix = "user-";
        var at = rawValue.IndexOf('@');
        if (at < 0 || !string.Equals(rawValue[(at + 1)..], domain, StringComparison.Ordinal))
        {
            return false;
        }

        var local = rawValue[..at];
        if (local.Length != prefix.Length + 8 || !local.StartsWith(prefix, StringComparison.Ordinal))
        {
            return false;
        }

        for (var i = prefix.Length; i < local.Length; i++)
        {
            if (!IsLowerHexDigit(local[i]))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>Exact shape of <see cref="GeneratePhone"/>'s output: <c>+1-555-01</c> + exactly 2 digits.
    /// Collision bound: this is a NANPA-reserved-for-fiction number range — no real subscriber can legitimately
    /// hold a number in <c>555-0100</c>-<c>555-0199</c>, so a genuine customer phone number can never
    /// authentically fall in this format; a false match here would require a customer-supplied value that is
    /// itself already fictional/reserved, which carries nothing real to leak.</summary>
    private static bool IsSyntheticPhoneFormat(string rawValue)
    {
        const string prefix = "+1-555-01";
        return rawValue.Length == prefix.Length + 2 &&
               rawValue.StartsWith(prefix, StringComparison.Ordinal) &&
               char.IsAsciiDigit(rawValue[^1]) && char.IsAsciiDigit(rawValue[^2]);
    }

    /// <summary>Exact membership in the 144 (12×12) <c>"{first} {last}"</c> combinations <see cref="GenerateName"/>
    /// can ever produce. Collision bound: this is the WEAKEST bound of the five formats — these first/last name
    /// tokens were chosen to be plausible-looking, so a real customer coincidentally being named e.g. "Alex
    /// Rivera" is not astronomically unlikely the way the email/phone/generic formats are. This is a deliberate,
    /// accepted trade-off: the field is already classified <see cref="FieldClass.SyntheticPii"/> (a name field),
    /// so a false match here means, at worst, a genuinely-real name that happens to exactly match one of 144
    /// fixed strings is echoed back unchanged instead of re-synthesized — the SAME value that was ALREADY visible
    /// in this exact response (it is not a NEW disclosure relative to not having this feature; the response
    /// already contained it, whatever its origin, before this check runs). No wider name-shaped heuristic (e.g.
    /// "any two capitalized words") is used specifically because that would have a far higher false-positive
    /// rate against ordinary two-word content.</summary>
    private static bool IsSyntheticNameFormat(string rawValue) => SyntheticNameBank.Value.Contains(rawValue);

    private static readonly Lazy<HashSet<string>> SyntheticNameBank = new(() =>
    {
        var bank = new HashSet<string>(StringComparer.Ordinal);
        foreach (var first in FirstNameTokens)
        {
            foreach (var last in LastNameTokens)
            {
                bank.Add($"{first} {last}");
            }
        }

        return bank;
    });

    /// <summary>Exact shape of <see cref="GenerateFreeText"/>'s output: <c>[synthetic-text-</c> + 8 lowercase hex
    /// chars + <c>]</c>. Collision bound: the bracketed, hyphenated literal prefix is not a shape ordinary free
    /// text (descriptions/notes/comments) organically produces.</summary>
    private static bool IsSyntheticFreeTextFormat(string rawValue)
    {
        const string prefix = "[synthetic-text-";
        const string suffix = "]";
        if (rawValue.Length != prefix.Length + 8 + suffix.Length ||
            !rawValue.StartsWith(prefix, StringComparison.Ordinal) ||
            !rawValue.EndsWith(suffix, StringComparison.Ordinal))
        {
            return false;
        }

        for (var i = prefix.Length; i < prefix.Length + 8; i++)
        {
            if (!IsLowerHexDigit(rawValue[i]))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>Exact shape of <see cref="GenerateGeneric"/>'s output: <c>synthetic-</c> + exactly 12 lowercase
    /// hex chars. Collision bound: same literal-prefix + fixed-length-hex reasoning as the free-text format
    /// above, with a longer (12-char, 1-in-2^48) hex run.</summary>
    private static bool IsSyntheticGenericFormat(string rawValue)
    {
        const string prefix = "synthetic-";
        if (rawValue.Length != prefix.Length + 12 || !rawValue.StartsWith(prefix, StringComparison.Ordinal))
        {
            return false;
        }

        for (var i = prefix.Length; i < rawValue.Length; i++)
        {
            if (!IsLowerHexDigit(rawValue[i]))
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsLowerHexDigit(char c) => (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');

    /// <summary>ADR §7: the real email domain is NEVER preserved — it would leak the customer's own customer
    /// list (B2B scenario) or route staging mail traffic to a real mail server. Defaults to
    /// <see cref="AnonymizationOptions.SyntheticEmailDomain"/> (<c>example.com</c> unless a customer overrides
    /// it with their own staging/test domain).</summary>
    private static string GenerateEmail(byte[] seed, string domain)
    {
        var local = Convert.ToHexString(seed.AsSpan(0, 4)).ToLowerInvariant();
        return $"user-{local}@{domain}";
    }

    /// <summary>ADR §7: phone numbers are drawn from the NANPA-reserved-for-fiction 555-01XX range so they
    /// never route to a real subscriber.</summary>
    private static string GeneratePhone(byte[] seed)
    {
        var suffix = seed[0] % 100;
        return $"+1-555-01{suffix:D2}";
    }

    /// <summary>A small fixed token bank combined via seed bytes — deterministic, clearly fictitious
    /// first/last name pairing (mirrors the ADR §9 worked example, "Ayşe Yılmaz" → "Derya Koçak").</summary>
    private static string GenerateName(byte[] seed)
    {
        var first = FirstNameTokens[seed[0] % FirstNameTokens.Length];
        var last = LastNameTokens[seed[1] % LastNameTokens.Length];
        return $"{first} {last}";
    }

    /// <summary>ADR §7: free text (description/note/message/comment) never carries forward any fragment of
    /// the real text — it becomes an clearly-synthetic, deterministic label.</summary>
    private static string GenerateFreeText(byte[] seed) =>
        $"[synthetic-text-{Convert.ToHexString(seed.AsSpan(0, 4)).ToLowerInvariant()}]";

    /// <summary>Fallback for any other classified-PII field (address, SSN/IBAN-shaped values, etc.) with no
    /// dedicated generator — a deterministic, clearly-synthetic opaque token.</summary>
    private static string GenerateGeneric(byte[] seed) =>
        $"synthetic-{Convert.ToHexString(seed.AsSpan(0, 6)).ToLowerInvariant()}";

    /// <summary>Deterministic synthetic INTEGER text (v1.2.0 type-preservation fix — e.g. the reported
    /// <c>PageSize=10</c>/<c>PageIndex=0</c> query parameters, classified <see cref="FieldClass.SyntheticPii"/>
    /// under the unknown-field fail-safe): stays a plausible digit count (bounded to at most
    /// <see cref="MaxPlausibleDigits"/> so it never overflows a typical 32-bit consumer, per spec — deliberately
    /// capped regardless of how many digits the original had) and keeps the original's sign.</summary>
    private static string GenerateIntegerText(byte[] seed, string rawValue)
    {
        var magnitude = ComputeBoundedMagnitude(seed, rawValue);
        return IsNegative(rawValue) ? $"-{magnitude}" : magnitude.ToString(CultureInfo.InvariantCulture);
    }

    /// <summary>Deterministic synthetic DECIMAL text — same magnitude derivation as
    /// <see cref="GenerateIntegerText"/>, plus a two-digit synthetic fractional part so the replacement still
    /// looks like the decimal shape it is replacing (never a whole number where a fraction was).</summary>
    private static string GenerateDecimalText(byte[] seed, string rawValue)
    {
        var magnitude = ComputeBoundedMagnitude(seed, rawValue);
        var fraction = seed[4] % 100;
        var sign = IsNegative(rawValue) ? "-" : string.Empty;
        return $"{sign}{magnitude}.{fraction:D2}";
    }

    /// <summary>Deterministic synthetic boolean TEXT (<c>"true"</c>/<c>"false"</c>) — used only for
    /// route/query/header values whose raw text is spelled like a JSON boolean literal; a real JSON
    /// <c>true</c>/<c>false</c> leaf is never routed through this generator (see <see cref="SyntheticValueShape.Boolean"/>).</summary>
    private static string GenerateBooleanText(byte[] seed) => seed[0] % 2 == 0 ? "false" : "true";

    /// <summary>Digit budget cap for a synthetic integer/decimal magnitude — 9 decimal digits always fits
    /// comfortably inside <see cref="int"/> (max 2,147,483,647 / 10 digits), satisfying the "never overflow a
    /// typical 32-bit consumer" requirement regardless of the original value's own digit count.</summary>
    private const int MaxPlausibleDigits = 9;

    /// <summary>Derives a deterministic, bounded non-negative magnitude from the seed — roughly matching the
    /// original value's digit count for plausibility (a 2-digit <c>PageSize</c> synthesizes to another small
    /// number, not a 9-digit one), but always clamped to <see cref="MaxPlausibleDigits"/>.</summary>
    private static uint ComputeBoundedMagnitude(byte[] seed, string rawValue)
    {
        var digitBudget = Math.Clamp(CountLeadingDigits(rawValue), 1, MaxPlausibleDigits);
        var pool = (uint)Math.Pow(10, digitBudget);
        return BinaryPrimitives.ReadUInt32BigEndian(seed) % pool;
    }

    /// <summary>Counts the digits at the start of <paramref name="rawValue"/> (skipping a leading sign) — used
    /// only to size the synthetic magnitude's digit budget, never to recover or echo the original value itself.</summary>
    private static int CountLeadingDigits(string rawValue)
    {
        var count = 0;
        foreach (var ch in rawValue)
        {
            if (count == 0 && ch is '-' or '+')
            {
                continue;
            }

            if (!char.IsAsciiDigit(ch))
            {
                break;
            }

            count++;
        }

        return count == 0 ? 1 : count;
    }

    private static bool IsNegative(string rawValue) => rawValue.Length > 0 && rawValue[0] == '-';

    /// <summary>Detects the shape a route/query/header value (always transport TEXT — there is no JSON
    /// container type at that position) must preserve when synthesized: a plain integer, a decimal, a JSON
    /// boolean spelling, or otherwise ordinary text. Deliberately conservative — exponent notation
    /// (<c>1e10</c>) and anything else with an unexpected character falls back to <see cref="SyntheticValueShape.Text"/>
    /// rather than risk mis-detecting an opaque token (e.g. a zero-padded code) as numeric.</summary>
    public static SyntheticValueShape DetectTransportShape(string rawValue)
    {
        if (string.Equals(rawValue, "true", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(rawValue, "false", StringComparison.OrdinalIgnoreCase))
        {
            return SyntheticValueShape.Boolean;
        }

        var i = 0;
        if (rawValue.Length > 0 && rawValue[0] is '-' or '+')
        {
            i = 1;
        }

        if (i == rawValue.Length)
        {
            return SyntheticValueShape.Text;
        }

        var sawDigit = false;
        var sawDot = false;
        for (; i < rawValue.Length; i++)
        {
            var ch = rawValue[i];
            if (char.IsAsciiDigit(ch))
            {
                sawDigit = true;
                continue;
            }

            if (ch == '.' && !sawDot)
            {
                sawDot = true;
                continue;
            }

            return SyntheticValueShape.Text;
        }

        if (!sawDigit)
        {
            return SyntheticValueShape.Text;
        }

        return sawDot ? SyntheticValueShape.Decimal : SyntheticValueShape.Integer;
    }
}
