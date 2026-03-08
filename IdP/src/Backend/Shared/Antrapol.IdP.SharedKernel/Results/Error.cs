namespace Antrapol.IdP.SharedKernel.Results;

/// <summary>
/// Represents an error with a code, message, and type.
/// </summary>
#pragma warning disable CA1716 // Type name conflicts with reserved keyword - intentional naming for Result pattern
public sealed record Error(string Code, string Message, ErrorType Type = ErrorType.Failure)
#pragma warning restore CA1716
{
    /// <summary>
    /// Represents no error (null object pattern).
    /// </summary>
    public static readonly Error None = new(string.Empty, string.Empty, ErrorType.None);

    /// <summary>
    /// Creates a validation error.
    /// </summary>
    public static Error Validation(string code, string message) =>
        new(code, message, ErrorType.Validation);

    /// <summary>
    /// Creates a not found error.
    /// </summary>
    public static Error NotFound(string code, string message) =>
        new(code, message, ErrorType.NotFound);

    /// <summary>
    /// Creates a conflict error.
    /// </summary>
    public static Error Conflict(string code, string message) =>
        new(code, message, ErrorType.Conflict);

    /// <summary>
    /// Creates an unauthorized error.
    /// </summary>
    public static Error Unauthorized(string code, string message) =>
        new(code, message, ErrorType.Unauthorized);

    /// <summary>
    /// Creates a forbidden error.
    /// </summary>
    public static Error Forbidden(string code, string message) =>
        new(code, message, ErrorType.Forbidden);

    /// <summary>
    /// Creates a general failure error.
    /// </summary>
    public static Error Failure(string code, string message) =>
        new(code, message, ErrorType.Failure);
}

/// <summary>
/// Represents the type of error.
/// </summary>
public enum ErrorType
{
    None = 0,
    Failure = 1,
    Validation = 2,
    NotFound = 3,
    Conflict = 4,
    Unauthorized = 5,
    Forbidden = 6
}
