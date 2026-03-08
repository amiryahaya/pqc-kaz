using System.Text.RegularExpressions;

namespace Antrapol.IdP.Identity.Domain.ValueObjects;

/// <summary>
/// Represents a phone number value object in E.164 format.
/// </summary>
public sealed partial record PhoneNumber
{
    private static readonly Regex PhoneRegex = GeneratePhoneRegex();

    public string Value { get; }

    private PhoneNumber(string value)
    {
        Value = value;
    }

    public static PhoneNumber Create(string phoneNumber)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(phoneNumber);

        var normalized = Normalize(phoneNumber);
        if (!PhoneRegex.IsMatch(normalized))
        {
            throw new ArgumentException("Invalid phone number format. Must be E.164 format.", nameof(phoneNumber));
        }

        return new PhoneNumber(normalized);
    }

    public static bool TryCreate(string phoneNumber, out PhoneNumber? result)
    {
        result = null;
        if (string.IsNullOrWhiteSpace(phoneNumber))
            return false;

        var normalized = Normalize(phoneNumber);
        if (!PhoneRegex.IsMatch(normalized))
            return false;

        result = new PhoneNumber(normalized);
        return true;
    }

    private static string Normalize(string phoneNumber)
    {
        // Remove spaces, dashes, parentheses
        var digits = new string(phoneNumber.Where(c => char.IsDigit(c) || c == '+').ToArray());

        // Ensure it starts with +
        if (!digits.StartsWith('+'))
        {
            digits = "+" + digits;
        }

        return digits;
    }

    public override string ToString() => Value;

    public static implicit operator string(PhoneNumber phone) => phone.Value;

    [GeneratedRegex(@"^\+[1-9]\d{6,14}$", RegexOptions.Compiled)]
    private static partial Regex GeneratePhoneRegex();
}
