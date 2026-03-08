using Npgsql;
using OpenTelemetry.Logs;
using OpenTelemetry.Metrics;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;
using StackExchange.Redis;

namespace Antrapol.IdP.Api.Configuration;

/// <summary>
/// OpenTelemetry configuration for distributed tracing, metrics, and logging.
/// </summary>
public static class OpenTelemetryConfig
{
    public static IServiceCollection AddOpenTelemetryObservability(
        this IServiceCollection services,
        IConfiguration configuration,
        IHostEnvironment environment)
    {
        var serviceName = configuration["OpenTelemetry:ServiceName"] ?? "pqc-identity-api";
        var serviceVersion = typeof(OpenTelemetryConfig).Assembly.GetName().Version?.ToString() ?? "1.0.0";
        var otlpEndpoint = configuration["OpenTelemetry:OtlpEndpoint"] ?? "http://localhost:4317";

        services.AddOpenTelemetry()
            .ConfigureResource(resource => resource
                .AddService(
                    serviceName: serviceName,
                    serviceVersion: serviceVersion,
                    serviceInstanceId: Environment.MachineName)
                .AddAttributes(new Dictionary<string, object>
                {
                    ["deployment.environment"] = environment.EnvironmentName.ToLowerInvariant()
                }))
            .WithTracing(tracing =>
            {
                tracing
                    .AddSource(serviceName)
                    .AddAspNetCoreInstrumentation(options =>
                    {
                        options.RecordException = true;
                        options.Filter = context =>
                        {
                            // Skip health check endpoints in traces
                            var path = context.Request.Path.Value ?? string.Empty;
                            return !path.StartsWith("/health", StringComparison.OrdinalIgnoreCase) &&
                                   !path.StartsWith("/metrics", StringComparison.OrdinalIgnoreCase);
                        };
                    })
                    .AddHttpClientInstrumentation(options =>
                    {
                        options.RecordException = true;
                    })
                    .AddNpgsql()
                    .AddRedisInstrumentation();

                // Export to OTLP (Jaeger supports OTLP natively)
                tracing.AddOtlpExporter(options =>
                {
                    options.Endpoint = new Uri(otlpEndpoint);
                });

                // Console exporter is included in OTLP for dev environments
            })
            .WithMetrics(metrics =>
            {
                metrics
                    .AddAspNetCoreInstrumentation()
                    .AddHttpClientInstrumentation()
                    .AddRuntimeInstrumentation()
                    .AddMeter("Microsoft.AspNetCore.Hosting")
                    .AddMeter("Microsoft.AspNetCore.Server.Kestrel")
                    .AddMeter(serviceName);

                // Prometheus exporter for scraping
                metrics.AddPrometheusExporter();

                // OTLP exporter
                metrics.AddOtlpExporter(options =>
                {
                    options.Endpoint = new Uri(otlpEndpoint);
                });
            });

        return services;
    }

    /// <summary>
    /// Configures Redis connection for OpenTelemetry instrumentation.
    /// </summary>
    public static void ConfigureRedisInstrumentation(
        this IServiceProvider services,
        IConnectionMultiplexer redis)
    {
        // Redis instrumentation is automatically added when AddRedisInstrumentation() is called
        // This method can be used for additional configuration if needed
    }
}
