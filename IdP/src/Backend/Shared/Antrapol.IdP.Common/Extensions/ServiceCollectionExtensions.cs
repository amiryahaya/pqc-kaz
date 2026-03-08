using Microsoft.Extensions.DependencyInjection;
using Antrapol.IdP.Common.Data;

namespace Antrapol.IdP.Common.Extensions;

/// <summary>
/// Extension methods for IServiceCollection.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds the database connection factory with the specified connection string.
    /// </summary>
    public static IServiceCollection AddDatabase(
        this IServiceCollection services,
        string connectionString)
    {
        DapperTypeHandlers.Register();

        services.AddSingleton<IDbConnectionFactory>(
            new NpgsqlConnectionFactory(connectionString));

        return services;
    }
}
