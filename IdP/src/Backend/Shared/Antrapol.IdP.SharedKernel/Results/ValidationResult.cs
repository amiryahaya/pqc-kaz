namespace Antrapol.IdP.SharedKernel.Results;

/// <summary>
/// Represents a validation result with multiple errors.
/// </summary>
public sealed class ValidationResult : Result
{
    private ValidationResult(Error[] errors)
        : base(false, errors.Length > 0 ? errors[0] : Error.None)
    {
        Errors = errors;
    }

    public Error[] Errors { get; }

    public static ValidationResult WithErrors(params Error[] errors) => new(errors);

#pragma warning disable CA1000 // Do not declare static members on generic types - factory methods are intentional
    public static ValidationResult<T> WithErrors<T>(params Error[] errors) =>
        ValidationResult<T>.WithErrors(errors);
#pragma warning restore CA1000
}

/// <summary>
/// Represents a validation result with multiple errors for type T.
/// </summary>
#pragma warning disable CA1000 // Do not declare static members on generic types - factory methods are intentional
public sealed class ValidationResult<T> : Result<T>
{
    private ValidationResult(Error[] errors)
        : base(errors.Length > 0 ? errors[0] : Error.None)
    {
        Errors = errors;
    }

    public Error[] Errors { get; }

    public static ValidationResult<T> WithErrors(params Error[] errors) => new(errors);
}
#pragma warning restore CA1000
