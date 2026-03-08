using System.Data;

namespace Antrapol.IdP.Common.Data;

/// <summary>
/// Factory for creating database connections.
/// </summary>
public interface IDbConnectionFactory
{
    /// <summary>
    /// Creates a new database connection.
    /// </summary>
    Task<IDbConnection> CreateConnectionAsync(CancellationToken ct = default);
}
