namespace Antrapol.IdP.SharedKernel.Results;

/// <summary>
/// Represents the result of an operation that does not return a value.
/// </summary>
public class Result
{
    protected Result(bool isSuccess, Error error)
    {
        if (isSuccess && error != Error.None)
        {
            throw new InvalidOperationException("Success result cannot have an error.");
        }

        if (!isSuccess && error == Error.None)
        {
            throw new InvalidOperationException("Failure result must have an error.");
        }

        IsSuccess = isSuccess;
        Error = error;
    }

    public bool IsSuccess { get; }
    public bool IsFailure => !IsSuccess;
    public Error Error { get; }

    public static Result Success() => new(true, Error.None);
    public static Result Failure(Error error) => new(false, error);

#pragma warning disable CA1000 // Do not declare static members on generic types - factory methods are intentional
    public static Result<T> Success<T>(T value) => Result<T>.Success(value);
    public static Result<T> Failure<T>(Error error) => Result<T>.Failure(error);
#pragma warning restore CA1000

    /// <summary>
    /// Executes the appropriate action based on the result state.
    /// </summary>
    public TResult Match<TResult>(Func<TResult> onSuccess, Func<Error, TResult> onFailure)
        => IsSuccess ? onSuccess() : onFailure(Error);

    /// <summary>
    /// Executes the appropriate action based on the result state.
    /// </summary>
    public async Task<TResult> MatchAsync<TResult>(
        Func<Task<TResult>> onSuccess,
        Func<Error, Task<TResult>> onFailure)
        => IsSuccess ? await onSuccess() : await onFailure(Error);
}

/// <summary>
/// Represents the result of an operation that returns a value of type T.
/// </summary>
#pragma warning disable CA1000 // Do not declare static members on generic types - factory methods are intentional
public class Result<T> : Result
{
    private readonly T? _value;

    private Result(T value) : base(true, Error.None)
    {
        _value = value;
    }

    protected internal Result(Error error) : base(false, error)
    {
        _value = default;
    }

    public T Value => IsSuccess
        ? _value!
        : throw new InvalidOperationException("Cannot access value of a failed result.");

    public static Result<T> Success(T value) => new(value);
    public new static Result<T> Failure(Error error) => new(error);

    /// <summary>
    /// Implicitly converts a value to a successful result.
    /// </summary>
    public static implicit operator Result<T>(T value) => Success(value);

    /// <summary>
    /// Implicitly converts an error to a failed result.
    /// </summary>
    public static implicit operator Result<T>(Error error) => Failure(error);

    /// <summary>
    /// Executes the appropriate action based on the result state.
    /// </summary>
    public TResult Match<TResult>(Func<T, TResult> onSuccess, Func<Error, TResult> onFailure)
        => IsSuccess ? onSuccess(_value!) : onFailure(Error);

    /// <summary>
    /// Executes the appropriate action based on the result state.
    /// </summary>
    public async Task<TResult> MatchAsync<TResult>(
        Func<T, Task<TResult>> onSuccess,
        Func<Error, Task<TResult>> onFailure)
        => IsSuccess ? await onSuccess(_value!) : await onFailure(Error);

    /// <summary>
    /// Maps the value to a new type if successful.
    /// </summary>
    public Result<TNew> Map<TNew>(Func<T, TNew> mapper)
        => IsSuccess ? Result<TNew>.Success(mapper(_value!)) : Result<TNew>.Failure(Error);

    /// <summary>
    /// Binds to another result if successful.
    /// </summary>
    public Result<TNew> Bind<TNew>(Func<T, Result<TNew>> binder)
        => IsSuccess ? binder(_value!) : Result<TNew>.Failure(Error);

    /// <summary>
    /// Binds to another result if successful (async).
    /// </summary>
    public async Task<Result<TNew>> BindAsync<TNew>(Func<T, Task<Result<TNew>>> binder)
        => IsSuccess ? await binder(_value!) : Result<TNew>.Failure(Error);
}
#pragma warning restore CA1000
