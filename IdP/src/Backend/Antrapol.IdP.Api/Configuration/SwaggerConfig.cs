using Microsoft.AspNetCore.OpenApi;

namespace Antrapol.IdP.Api.Configuration;

/// <summary>
/// Swagger/OpenAPI configuration using .NET 10 built-in OpenAPI.
/// </summary>
public static class SwaggerConfig
{
    public static IServiceCollection AddSwaggerDocumentation(this IServiceCollection services)
    {
        // Use .NET 10 built-in OpenAPI support
        services.AddOpenApi("v1", options =>
        {
            options.AddDocumentTransformer((document, context, ct) =>
            {
                document.Info.Title = "PQC Identity Platform API";
                document.Info.Version = "v1";
                document.Info.Description = "Post-Quantum Cryptography Digital Identity Platform API";
                return Task.CompletedTask;
            });
        });

        // Add Swagger UI (still uses Swashbuckle for the UI)
        services.AddEndpointsApiExplorer();

        return services;
    }

    public static IApplicationBuilder UseSwaggerDocumentation(
        this WebApplication app,
        IHostEnvironment environment)
    {
        // Use .NET 10 built-in OpenAPI endpoint
        app.MapOpenApi("/api-docs/{documentName}.json");

        // Swagger UI for interactive documentation
        app.UseSwaggerUI(options =>
        {
            options.SwaggerEndpoint("/api-docs/v1.json", "PQC Identity API v1");
            options.RoutePrefix = "swagger";
            options.DocumentTitle = "PQC Identity Platform API";

            if (environment.IsDevelopment())
            {
                options.EnableDeepLinking();
                options.EnableTryItOutByDefault();
            }
        });

        return app;
    }
}
