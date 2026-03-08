using Antrapol.IdP.SharedKernel.Results;

namespace Antrapol.IdP.SharedKernel.Handlers;

/// <summary>
/// Defines a handler for a command that returns a result with a value.
/// </summary>
/// <typeparam name="TCommand">The type of command to handle.</typeparam>
/// <typeparam name="TResult">The type of value returned on success.</typeparam>
public interface ICommandHandler<in TCommand, TResult>
{
    Task<Result<TResult>> HandleAsync(TCommand command, CancellationToken ct = default);
}

/// <summary>
/// Defines a handler for a command that returns a result without a value.
/// </summary>
/// <typeparam name="TCommand">The type of command to handle.</typeparam>
public interface ICommandHandler<in TCommand>
{
    Task<Result> HandleAsync(TCommand command, CancellationToken ct = default);
}
