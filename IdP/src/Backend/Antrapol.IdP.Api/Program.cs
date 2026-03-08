using Carter;
using Antrapol.IdP.Admin.Api;
using Antrapol.IdP.Api.Configuration;
using Antrapol.IdP.Certificate.Api;
using Antrapol.IdP.Common.Extensions;
using Antrapol.IdP.Crypto.Api;
using Antrapol.IdP.Identity.Api;
using Serilog;

Log.Logger = new LoggerConfiguration()
    .WriteTo.Console(formatProvider: System.Globalization.CultureInfo.InvariantCulture)
    .CreateBootstrapLogger();

try
{
    Log.Information("Starting PQC Identity API");

    var builder = WebApplication.CreateBuilder(args);

    // Serilog
    builder.Host.UseSerilogLogging();

    // OpenTelemetry
    builder.Services.AddOpenTelemetryObservability(builder.Configuration, builder.Environment);

    // Swagger
    builder.Services.AddSwaggerDocumentation();

    // Health checks
    builder.Services.AddHealthCheckServices(builder.Configuration);

    // Database
    var connectionString = builder.Configuration.GetConnectionString("DefaultConnection")
        ?? "Host=localhost;Database=pqc_identity;Username=postgres;Password=postgres";
    builder.Services.AddDatabase(connectionString);

    // Carter for minimal API modules
    builder.Services.AddCarter();

    // Register modules
    builder.Services.AddIdentityModule();
    builder.Services.AddCertificateModule(builder.Configuration);
    builder.Services.AddCryptoModule();
    builder.Services.AddAdminModule();

    // CORS
    builder.Services.AddCors(options =>
    {
        options.AddDefaultPolicy(policy =>
        {
            policy.AllowAnyOrigin()
                  .AllowAnyMethod()
                  .AllowAnyHeader();
        });
    });

    // ProblemDetails
    builder.Services.AddProblemDetails();

    var app = builder.Build();

    // Exception handling
    app.UseExceptionHandling();

    // Serilog request logging
    app.UseSerilogRequestLogging();

    // CORS
    app.UseCors();

    // Swagger
    app.UseSwaggerDocumentation(app.Environment);

    // Health checks
    app.MapHealthCheckEndpoints();

    // Prometheus metrics endpoint
    app.UseOpenTelemetryPrometheusScrapingEndpoint();

    // Carter modules
    app.MapCarter();

    // Root endpoint
    app.MapGet("/", () => Results.Ok(new
    {
        Service = "PQC Identity Platform API",
        Version = "1.0.0",
        Status = "Running"
    }));

    app.Run();
}
catch (Exception ex)
{
    Log.Fatal(ex, "Application terminated unexpectedly");
}
finally
{
    Log.CloseAndFlush();
}
