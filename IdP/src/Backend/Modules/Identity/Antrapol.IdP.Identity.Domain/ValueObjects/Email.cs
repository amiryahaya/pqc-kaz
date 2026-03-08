using System.Text.RegularExpressions;

namespace Antrapol.IdP.Identity.Domain.ValueObjects;

/// <summary>
/// Represents an email address value object.
/// </summary>
public sealed partial record Email
{
    private static readonly Regex EmailRegex = GenerateEmailRegex();

    public string Value { get; }

    private Email(string value)
    {
        Value = value.ToLowerInvariant();
    }

    public static Email Create(string email)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(email);

        var trimmed = email.Trim();
        if (!EmailRegex.IsMatch(trimmed))
        {
            throw new ArgumentException("Invalid email format.", nameof(email));
        }

        return new Email(trimmed);
    }

    public static bool TryCreate(string email, out Email? result)
    {
        result = null;
        if (string.IsNullOrWhiteSpace(email))
            return false;

        var trimmed = email.Trim();
        if (!EmailRegex.IsMatch(trimmed))
            return false;

        result = new Email(trimmed);
        return true;
    }

    public override string ToString() => Value;

    public static implicit operator string(Email email) => email.Value;

    [GeneratedRegex(@"^[^@\s]+@[^@\s]+\.[^@\s]+$", RegexOptions.Compiled | RegexOptions.IgnoreCase)]
    private static partial Regex GenerateEmailRegex();
}
