using System.Globalization;
using Serilog;
using Serilog.Events;
using Serilog.Sinks.OpenTelemetry;

namespace Antrapol.IdP.Api.Configuration;

/// <summary>
/// Serilog configuration for structured logging.
/// </summary>
public static class SerilogConfig
{
    public static IHostBuilder UseSerilogLogging(this IHostBuilder hostBuilder)
    {
        return hostBuilder.UseSerilog((context, services, configuration) =>
        {
            var environment = context.HostingEnvironment;
            var config = context.Configuration;

            var seqUrl = config["Serilog:SeqUrl"] ?? "http://localhost:5341";
            var otlpEndpoint = config["OpenTelemetry:OtlpEndpoint"] ?? "http://localhost:4317";

            configuration
                .MinimumLevel.Information()
                .MinimumLevel.Override("Microsoft", LogEventLevel.Warning)
                .MinimumLevel.Override("Microsoft.Hosting.Lifetime", LogEventLevel.Information)
                .MinimumLevel.Override("Microsoft.AspNetCore.Hosting", LogEventLevel.Warning)
                .MinimumLevel.Override("Microsoft.AspNetCore.Routing", LogEventLevel.Warning)
                .MinimumLevel.Override("System", LogEventLevel.Warning)
                .Enrich.FromLogContext()
                .Enrich.WithMachineName()
                .Enrich.WithThreadId()
                .Enrich.WithProperty("Application", "PqcIdentity.Api")
                .Enrich.WithProperty("Environment", environment.EnvironmentName);

            // Always log to console
            configuration.WriteTo.Console(
                outputTemplate: "[{Timestamp:HH:mm:ss} {Level:u3}] {Message:lj} {Properties:j}{NewLine}{Exception}",
                formatProvider: CultureInfo.InvariantCulture);

            // In Development, log to Seq
            if (environment.IsDevelopment())
            {
                configuration
                    .MinimumLevel.Debug()
                    .WriteTo.Seq(seqUrl, formatProvider: CultureInfo.InvariantCulture);
            }

            // OpenTelemetry log export
            configuration.WriteTo.OpenTelemetry(options =>
            {
                options.Endpoint = otlpEndpoint;
                options.Protocol = OtlpProtocol.Grpc;
                options.ResourceAttributes = new Dictionary<string, object>
                {
                    ["service.name"] = config["OpenTelemetry:ServiceName"] ?? "pqc-identity-api",
                    ["deployment.environment"] = environment.EnvironmentName.ToLowerInvariant()
                };
            });
        });
    }

    /// <summary>
    /// Adds request logging middleware configuration.
    /// </summary>
    public static IApplicationBuilder UseSerilogRequestLogging(this IApplicationBuilder app)
    {
        return app.UseSerilogRequestLogging(options =>
        {
            options.EnrichDiagnosticContext = (diagnosticContext, httpContext) =>
            {
                diagnosticContext.Set("RequestHost", httpContext.Request.Host.Value ?? "unknown");
                diagnosticContext.Set("RequestScheme", httpContext.Request.Scheme);
                diagnosticContext.Set("UserAgent", httpContext.Request.Headers.UserAgent.ToString());

                if (httpContext.User.Identity?.IsAuthenticated == true)
                {
                    var userId = httpContext.User.FindFirst("sub")?.Value;
                    if (userId is not null)
                    {
                        diagnosticContext.Set("UserId", userId);
                    }
                }
            };

            // Customize the message template
            options.MessageTemplate = "HTTP {RequestMethod} {RequestPath} responded {StatusCode} in {Elapsed:0.0000} ms";

            // Skip health check endpoints
            options.GetLevel = (httpContext, elapsed, ex) =>
            {
                var path = httpContext.Request.Path.Value ?? string.Empty;
                if (path.StartsWith("/health", StringComparison.OrdinalIgnoreCase))
                {
                    return LogEventLevel.Verbose;
                }

                return ex != null
                    ? LogEventLevel.Error
                    : httpContext.Response.StatusCode >= 500
                        ? LogEventLevel.Error
                        : LogEventLevel.Information;
            };
        });
    }
}
