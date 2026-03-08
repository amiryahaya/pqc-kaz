using Antrapol.IdP.SharedKernel.Results;

namespace Antrapol.IdP.SharedKernel.Handlers;

/// <summary>
/// Defines a handler for a query that returns a result with a value.
/// </summary>
/// <typeparam name="TQuery">The type of query to handle.</typeparam>
/// <typeparam name="TResult">The type of value returned on success.</typeparam>
public interface IQueryHandler<in TQuery, TResult>
{
    Task<Result<TResult>> HandleAsync(TQuery query, CancellationToken ct = default);
}
