namespace Jakapil.Capture.Anonymization;

/// <summary>
/// Deterministic synthetic PII generator (ADR-0002 §7):
/// <c>synthetic = generator(kind, HMAC(key, tenant‖project‖env‖kind‖rawValue))</c>. Determinism is a
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
    public static string Generate(
        string? fieldName, string rawValue, ReadOnlySpan<byte> key, AnonymizationScope scope, string emailDomain)
    {
        var normalized = fieldName is null ? string.Empty : FieldNameRules.Normalize(fieldName);
        var kindForSeed = normalized.Length == 0 ? "generic" : normalized;
        var seed = FingerprintGenerator.ComputeSyntheticSeed(key, scope.TenantId, scope.ProjectId, scope.Environment, kindForSeed, rawValue);

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
}
