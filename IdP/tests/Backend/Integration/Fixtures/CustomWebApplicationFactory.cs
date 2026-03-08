using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace PqcIdentity.Tests.Integration.Fixtures;

/// <summary>
/// Custom web application factory for integration tests.
/// </summary>
public class CustomWebApplicationFactory : WebApplicationFactory<Program>
{
    public string? ConnectionString { get; set; }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureAppConfiguration((context, config) =>
        {
            // Override configuration for testing
            var testSettings = new Dictionary<string, string?>
            {
                ["ConnectionStrings:DefaultConnection"] = ConnectionString ?? "Host=localhost;Database=test;",
                ["Jwt:Secret"] = "test-secret-key-for-jwt-signing-minimum-32-characters",
                ["Jwt:Issuer"] = "PqcIdentity.Tests",
                ["Jwt:Audience"] = "PqcIdentity.Tests",
                ["Jwt:ExpirationMinutes"] = "60"
            };

            config.AddInMemoryCollection(testSettings);
        });

        builder.ConfigureServices(services =>
        {
            // Remove any production services and replace with test doubles
            // Add any test-specific services here
        });

        builder.UseEnvironment("Testing");
    }
}
