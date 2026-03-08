using HealthChecks.UI.Client;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;

namespace Antrapol.IdP.Api.Configuration;

/// <summary>
/// Health check configuration for the API.
/// </summary>
public static class HealthCheckConfig
{
    public static IServiceCollection AddHealthCheckServices(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        var connectionString = configuration.GetConnectionString("DefaultConnection")
            ?? "Host=localhost;Database=pqc_identity;Username=postgres;Password=postgres";
        var redisConnection = configuration.GetConnectionString("Redis")
            ?? "localhost:6379";

        services.AddHealthChecks()
            .AddNpgSql(connectionString, name: "postgresql", tags: ["database", "ready"])
            .AddRedis(redisConnection, name: "redis", tags: ["cache", "ready"]);

        return services;
    }

    public static IEndpointRouteBuilder MapHealthCheckEndpoints(this IEndpointRouteBuilder endpoints)
    {
        // Liveness probe - basic check that the app is running
        endpoints.MapHealthChecks("/health/live", new HealthCheckOptions
        {
            Predicate = _ => false // No checks, just returns healthy if app is running
        });

        // Readiness probe - checks all dependencies
        endpoints.MapHealthChecks("/health/ready", new HealthCheckOptions
        {
            Predicate = check => check.Tags.Contains("ready"),
            ResponseWriter = UIResponseWriter.WriteHealthCheckUIResponse
        });

        // Full health check with all details
        endpoints.MapHealthChecks("/health", new HealthCheckOptions
        {
            ResponseWriter = UIResponseWriter.WriteHealthCheckUIResponse
        });

        return endpoints;
    }
}
