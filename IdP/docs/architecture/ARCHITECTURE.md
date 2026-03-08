# PQC Digital Identity Platform - Architecture Document

**Version:** 1.0.0
**Last Updated:** 2025-12-01
**Status:** Draft

---

## Table of Contents

1. [Overview](#overview)
2. [System Architecture](#system-architecture)
3. [Technology Stack](#technology-stack)
4. [Backend Architecture](#backend-architecture)
5. [Client Applications](#client-applications)
6. [Cryptographic Architecture](#cryptographic-architecture)
7. [Authentication Flows](#authentication-flows)
8. [Certificate Management](#certificate-management)
9. [Multi-Tenancy](#multi-tenancy)
10. [Deployment Models](#deployment-models)
11. [Folder Structure](#folder-structure)
12. [API Design](#api-design)
13. [Security Considerations](#security-considerations)
14. [HSM Integration](#hsm-integration)
15. [User Registration Flow](#user-registration-flow)
16. [Account Recovery Flow](#account-recovery-flow)

### Related Documents

- [REGISTRATION_FLOW.md](./REGISTRATION_FLOW.md) - Detailed registration sequence with secret sharing
- [ACCOUNT_RECOVERY_FLOW.md](./ACCOUNT_RECOVERY_FLOW.md) - Account recovery process using secret sharing
- [AUTHENTICATION_FLOW.md](./AUTHENTICATION_FLOW.md) - OIDC/OAuth 2.0 authentication to relying parties
- [QR_CODE_AUTHENTICATION.md](./QR_CODE_AUTHENTICATION.md) - QR code authentication for relying parties
- [DEVICE_MANAGEMENT.md](./DEVICE_MANAGEMENT.md) - Multi-device management, pairing, and removal
- [CERTIFICATE_RENEWAL.md](./CERTIFICATE_RENEWAL.md) - Certificate lifecycle and renewal flows
- [TENANT_ONBOARDING.md](./TENANT_ONBOARDING.md) - Organization onboarding and setup
- [APP_ATTESTATION.md](./APP_ATTESTATION.md) - App attestation and device integrity verification
- [CERTIFICATE_ISSUANCE.md](./CERTIFICATE_ISSUANCE.md) - Backend certificate issuance flow and PKI management
- [DEVELOPMENT_SETUP.md](../deployment/DEVELOPMENT_SETUP.md) - Development environment setup with SoftHSM2

---

## Overview

### Purpose

Enterprise-grade Post-Quantum Cryptography (PQC) Digital Identity Platform providing:

- **Digital ID Mobile/Desktop Apps** - Native applications for identity management
- **Identity Provider (IdP)** - OIDC/OAuth 2.0 compliant authentication
- **Private Certificate Authority** - PQC X.509 certificate issuance
- **FIDO2/WebAuthn Support** - Passwordless authentication
- **PQC-Signed JWTs** - Quantum-resistant token signing

### Key Features

| Feature | Description |
|---------|-------------|
| Multi-Organization | Each organization picks one primary PQC algorithm |
| Multiple PQC Algorithms | ML-DSA (Dilithium), KAZ-SIGN supported |
| OIDC/OAuth 2.0 | Standard identity protocols |
| FIDO2/WebAuthn | Passwordless authentication |
| PQC-JWT | Post-quantum signed JSON Web Tokens |
| Private CA | Per-organization certificate authority |
| SaaS + On-Premise | Flexible deployment options |

### Primary PQC Algorithms

| Algorithm | Type | Security Levels | Source |
|-----------|------|-----------------|--------|
| **ML-DSA** (Dilithium) | Signature | 44, 65, 87 | .NET 10 Native |
| **KAZ-SIGN** | Signature | 128, 192, 256 | Custom Native Library |
| **ML-KEM** (Kyber) | KEM | 512, 768, 1024 | .NET 10 Native |
| **KAZ-KEM** | KEM | 128, 192, 256 | Custom Native Library |

---

## System Architecture

### High-Level Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        PQC Digital Identity Platform                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Native Clients                                                             │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐                   │
│  │  Android  │ │    iOS    │ │   macOS   │ │  Windows  │                   │
│  │  Kotlin   │ │   Swift   │ │   Swift   │ │ WinUI 3   │                   │
│  │           │ │           │ │           │ │           │                   │
│  │ KAZ-SIGN  │ │ KAZ-SIGN  │ │ KAZ-SIGN  │ │ KAZ-SIGN  │                   │
│  │ (JNI)     │ │ (Native)  │ │ (Native)  │ │ (P/Invoke)│                   │
│  └─────┬─────┘ └─────┬─────┘ └─────┬─────┘ └─────┬─────┘                   │
│        │             │             │             │                          │
│        └─────────────┴──────┬──────┴─────────────┘                          │
│                             │ REST API / HTTPS                              │
│                             ▼                                               │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                      C# Backend API (.NET 10)                         │  │
│  │                                                                       │  │
│  │   ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐  │  │
│  │   │ Identity │ │  Cert    │ │  Admin   │ │  Crypto  │ │  Shared  │  │  │
│  │   │  Module  │ │  Module  │ │  Module  │ │  Module  │ │  Kernel  │  │  │
│  │   └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────┘  │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  Web Clients (C# Blazor)                                                    │
│  ┌───────────────────┐ ┌───────────────────┐                               │
│  │   Admin Portal    │ │   User Portal     │                               │
│  │   (Blazor WASM)   │ │   (Blazor WASM)   │                               │
│  └───────────────────┘ └───────────────────┘                               │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Component Interaction

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              API Gateway                                     │
│                    (Rate Limiting, TLS Termination)                         │
└─────────────────────────────────┬───────────────────────────────────────────┘
                                  │
        ┌─────────────────────────┼─────────────────────────┐
        │                         │                         │
        ▼                         ▼                         ▼
┌───────────────┐       ┌─────────────────┐       ┌─────────────────┐
│    Identity   │       │   Certificate   │       │     Admin       │
│    Module     │       │     Module      │       │     Module      │
│               │       │                 │       │                 │
│ • OIDC/OAuth  │       │ • Private CA    │       │ • Org Mgmt      │
│ • FIDO2       │       │ • CSR Processing│       │ • User Mgmt     │
│ • PQC-JWT     │       │ • Cert Issuance │       │ • Policy Mgmt   │
│ • Session Mgmt│       │ • Revocation    │       │ • Audit Logs    │
└───────┬───────┘       └────────┬────────┘       └────────┬────────┘
        │                        │                         │
        └────────────────────────┼─────────────────────────┘
                                 │
                                 ▼
              ┌──────────────────────────────────────┐
              │           Shared Services            │
              │                                      │
              │  ┌────────────┐  ┌────────────────┐  │
              │  │   Crypto   │  │   Key Vault    │  │
              │  │   Module   │  │   Service      │  │
              │  └────────────┘  └────────────────┘  │
              │  ┌────────────┐  ┌────────────────┐  │
              │  │   Tenant   │  │   Event Bus    │  │
              │  │   Service  │  │   (Optional)   │  │
              │  └────────────┘  └────────────────┘  │
              └──────────────────────────────────────┘
                                 │
                                 ▼
              ┌──────────────────────────────────────┐
              │            Data Stores               │
              │                                      │
              │  PostgreSQL │ Redis │ Blob Storage   │
              └──────────────────────────────────────┘
```

---

## Technology Stack

### Backend

| Component | Technology |
|-----------|------------|
| Runtime | .NET 10 |
| Language | C# 13 |
| API Framework | ASP.NET Core Minimal APIs + Carter |
| API Documentation | Swagger/Swashbuckle (OpenAPI) |
| Database | PostgreSQL 16+ |
| Cache | Redis |
| Data Access | Dapper (Micro ORM) |
| Error Handling | Result Pattern + ProblemDetails (RFC 9457) |
| Logging | Serilog (Structured Logging) |
| Observability | OpenTelemetry (Traces, Metrics) |
| PQC (Native) | ML-DSA, ML-KEM (.NET 10 built-in) |
| PQC (Custom) | KAZ-SIGN, KAZ-KEM (P/Invoke) |

### Observability Stack

| Component | Technology | Backends |
|-----------|------------|----------|
| Tracing | OpenTelemetry | Jaeger (Dev) / Azure Monitor (Prod) |
| Metrics | OpenTelemetry | Prometheus + Grafana |
| Logging | Serilog | Seq (Dev) / Elasticsearch (Prod) |
| Dashboards | Grafana | Custom dashboards |

### Web Clients

| Component | Technology |
|-----------|------------|
| Admin Portal | Blazor WebAssembly |
| User Portal | Blazor WebAssembly |
| UI Framework | MudBlazor or Fluent UI |

### Native Clients

| Platform | Technology | PQC Integration |
|----------|------------|-----------------|
| Android | Kotlin | JNI to libkazsign.so |
| iOS | Swift | KazSignNative.xcframework |
| macOS | Swift | KazSignNative.xcframework |
| Windows | C# WinUI 3 | P/Invoke to libkazsign.dll |

### Infrastructure

| Component | Technology |
|-----------|------------|
| Container | Docker |
| Orchestration | Kubernetes |
| CI/CD | GitHub Actions |
| IaC | Terraform |
| Key Vault | Azure Key Vault / HashiCorp Vault |

---

## Backend Architecture

### Modular Monolith Pattern

The backend uses a **Modular Monolith** architecture, allowing:
- Clear module boundaries
- Independent development and testing per module
- Easy extraction to microservices later if needed
- Single deployment unit

### Module Structure

Each module follows Clean Architecture with Carter for API organization:

```
Module/
├── ModuleName.Api/                 # API Layer (Carter Modules)
│   ├── Endpoints/                  # Carter ICarterModule implementations
│   │   ├── UserEndpoints.cs
│   │   ├── DeviceEndpoints.cs
│   │   └── ...
│   ├── Middleware/
│   └── ModuleRegistration.cs
│
├── ModuleName.Application/         # Use Cases (Result Pattern)
│   ├── Commands/
│   │   └── CommandName/
│   │       ├── CommandNameCommand.cs
│   │       └── CommandNameHandler.cs  # Returns Result<T>
│   ├── Queries/
│   │   └── QueryName/
│   │       ├── QueryNameQuery.cs
│   │       └── QueryNameHandler.cs    # Returns Result<T>
│   ├── DTOs/
│   ├── Interfaces/
│   └── Validators/
│
├── ModuleName.Domain/              # Entities, Business Logic
│   ├── Entities/
│   ├── Enums/
│   ├── Events/
│   ├── Interfaces/
│   └── ValueObjects/
│
└── ModuleName.Infrastructure/      # External Concerns (Dapper)
    ├── Persistence/
    │   ├── ConnectionFactory.cs    # Npgsql connection management
    │   └── Repositories/           # Dapper-based repositories
    ├── Services/
    └── DependencyInjection.cs
```

### Handler Pattern with Result Pattern (No MediatR)

Using plain interfaces with Result pattern for explicit error handling:

```csharp
// Result Pattern
public sealed class Result<T>
{
    public bool IsSuccess { get; }
    public bool IsFailure => !IsSuccess;
    public T? Value { get; }
    public Error? Error { get; }

    private Result(T value) { IsSuccess = true; Value = value; }
    private Result(Error error) { IsSuccess = false; Error = error; }

    public static Result<T> Success(T value) => new(value);
    public static Result<T> Failure(Error error) => new(error);

    public TResult Match<TResult>(
        Func<T, TResult> onSuccess,
        Func<Error, TResult> onFailure) =>
        IsSuccess ? onSuccess(Value!) : onFailure(Error!);
}

public sealed record Error(string Code, string Message, ErrorType Type = ErrorType.Failure);

public enum ErrorType
{
    Failure,
    Validation,
    NotFound,
    Conflict,
    Unauthorized,
    Forbidden
}

// Command Handler Interface
public interface ICommandHandler<TCommand, TResult>
{
    Task<Result<TResult>> HandleAsync(TCommand command, CancellationToken ct = default);
}

public interface ICommandHandler<TCommand>
{
    Task<Result> HandleAsync(TCommand command, CancellationToken ct = default);
}

// Query Handler Interface
public interface IQueryHandler<TQuery, TResult>
{
    Task<Result<TResult>> HandleAsync(TQuery query, CancellationToken ct = default);
}
```

### Carter Module Pattern

Using Carter for modular minimal API organization:

```csharp
// Example Carter Module
public class UserEndpoints : ICarterModule
{
    public void AddRoutes(IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/v1/identity/users")
            .WithTags("Users")
            .RequireAuthorization();

        group.MapGet("/me", GetCurrentUser)
            .WithName("GetCurrentUser")
            .WithSummary("Get current user profile")
            .Produces<UserResponse>(StatusCodes.Status200OK)
            .ProducesProblem(StatusCodes.Status401Unauthorized);

        group.MapPatch("/me", UpdateCurrentUser)
            .WithName("UpdateCurrentUser")
            .Accepts<UpdateUserRequest>("application/json")
            .Produces<UserResponse>(StatusCodes.Status200OK)
            .ProducesValidationProblem();
    }

    private static async Task<IResult> GetCurrentUser(
        IQueryHandler<GetUserQuery, UserDto> handler,
        ClaimsPrincipal user,
        CancellationToken ct)
    {
        var userId = user.GetUserId();
        var result = await handler.HandleAsync(new GetUserQuery(userId), ct);

        return result.Match(
            onSuccess: dto => Results.Ok(dto.ToResponse()),
            onFailure: error => error.ToProblemResult()
        );
    }
}
```

### ProblemDetails for Error Responses

Using RFC 9457 ProblemDetails for standardized error responses:

```csharp
// Error to ProblemDetails extension
public static class ErrorExtensions
{
    public static IResult ToProblemResult(this Error error)
    {
        var statusCode = error.Type switch
        {
            ErrorType.Validation => StatusCodes.Status400BadRequest,
            ErrorType.NotFound => StatusCodes.Status404NotFound,
            ErrorType.Conflict => StatusCodes.Status409Conflict,
            ErrorType.Unauthorized => StatusCodes.Status401Unauthorized,
            ErrorType.Forbidden => StatusCodes.Status403Forbidden,
            _ => StatusCodes.Status500InternalServerError
        };

        return Results.Problem(
            statusCode: statusCode,
            title: error.Type.ToString(),
            detail: error.Message,
            extensions: new Dictionary<string, object?>
            {
                ["errorCode"] = error.Code
            }
        );
    }
}

// Program.cs configuration
builder.Services.AddProblemDetails(options =>
{
    options.CustomizeProblemDetails = context =>
    {
        context.ProblemDetails.Extensions["traceId"] =
            Activity.Current?.Id ?? context.HttpContext.TraceIdentifier;
    };
});
```

### Dapper Data Access Pattern

Using Dapper for high-performance data access:

```csharp
// Connection Factory
public interface IDbConnectionFactory
{
    Task<NpgsqlConnection> CreateConnectionAsync(CancellationToken ct = default);
    Task<NpgsqlConnection> CreateTenantConnectionAsync(string tenantSlug, CancellationToken ct = default);
}

public class DbConnectionFactory : IDbConnectionFactory
{
    private readonly string _connectionString;

    public DbConnectionFactory(IConfiguration configuration)
    {
        _connectionString = configuration.GetConnectionString("Default")!;
    }

    public async Task<NpgsqlConnection> CreateConnectionAsync(CancellationToken ct = default)
    {
        var connection = new NpgsqlConnection(_connectionString);
        await connection.OpenAsync(ct);
        return connection;
    }

    public async Task<NpgsqlConnection> CreateTenantConnectionAsync(string tenantSlug, CancellationToken ct = default)
    {
        var connection = await CreateConnectionAsync(ct);
        // Set search path to tenant schema
        await connection.ExecuteAsync($"SET search_path TO tenant_{tenantSlug}, public");
        return connection;
    }
}

// Repository Example with Dapper
public class UserRepository : IUserRepository
{
    private readonly IDbConnectionFactory _connectionFactory;

    public UserRepository(IDbConnectionFactory connectionFactory)
    {
        _connectionFactory = connectionFactory;
    }

    public async Task<User?> GetByIdAsync(Guid id, CancellationToken ct = default)
    {
        await using var connection = await _connectionFactory.CreateTenantConnectionAsync(
            TenantContext.Current.Slug, ct);

        return await connection.QuerySingleOrDefaultAsync<User>(
            """
            SELECT id, email, display_name, status, created_at, updated_at
            FROM users
            WHERE id = @Id AND deleted_at IS NULL
            """,
            new { Id = id });
    }

    public async Task<Guid> CreateAsync(User user, CancellationToken ct = default)
    {
        await using var connection = await _connectionFactory.CreateTenantConnectionAsync(
            TenantContext.Current.Slug, ct);

        return await connection.ExecuteScalarAsync<Guid>(
            """
            INSERT INTO users (email, email_normalized, display_name, status, created_at)
            VALUES (@Email, @EmailNormalized, @DisplayName, @Status, @CreatedAt)
            RETURNING id
            """,
            user);
    }
}
```

### Swagger/OpenAPI Configuration

Using Swashbuckle for API documentation:

```csharp
// Program.cs - Swagger Configuration
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    options.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "PQC Digital Identity Platform API",
        Version = "v1",
        Description = "Enterprise-grade Post-Quantum Cryptography Digital Identity Platform",
        Contact = new OpenApiContact
        {
            Name = "API Support",
            Email = "support@idp.example.com"
        }
    });

    // Bearer token authentication
    options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "JWT Authorization header using Bearer scheme",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.Http,
        Scheme = "bearer",
        BearerFormat = "JWT"
    });

    options.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    });

    // Include XML comments
    var xmlFile = $"{Assembly.GetExecutingAssembly().GetName().Name}.xml";
    var xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
    options.IncludeXmlComments(xmlPath);
});

// Enable Swagger UI
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(options =>
    {
        options.SwaggerEndpoint("/swagger/v1/swagger.json", "IdP API v1");
        options.RoutePrefix = "swagger";
    });
}
```

### OpenTelemetry Observability

Complete observability using OpenTelemetry for distributed tracing, metrics, and logging.

#### OpenTelemetry Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         OBSERVABILITY ARCHITECTURE                           │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   IdP API   │     │  Mobile App │     │  Web Portal │
│  (Backend)  │     │   (Client)  │     │  (Blazor)   │
└──────┬──────┘     └──────┬──────┘     └──────┬──────┘
       │                   │                   │
       └───────────────────┼───────────────────┘
                           │
                    OTLP (gRPC/HTTP)
                           │
              ┌────────────┴────────────┐
              │   OpenTelemetry         │
              │   Collector (Optional)  │
              └────────────┬────────────┘
                           │
       ┌───────────────────┼───────────────────┐
       │                   │                   │
       ▼                   ▼                   ▼
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Jaeger    │     │ Prometheus  │     │    Seq      │
│  (Traces)   │     │  (Metrics)  │     │   (Logs)    │
└─────────────┘     └─────────────┘     └─────────────┘
       │                   │                   │
       └───────────────────┼───────────────────┘
                           │
                           ▼
                    ┌─────────────┐
                    │   Grafana   │
                    │ (Dashboards)│
                    └─────────────┘
```

#### NuGet Packages

```xml
<!-- OpenTelemetry Core -->
<PackageReference Include="OpenTelemetry" Version="1.9.*" />
<PackageReference Include="OpenTelemetry.Extensions.Hosting" Version="1.9.*" />

<!-- Exporters -->
<PackageReference Include="OpenTelemetry.Exporter.OpenTelemetryProtocol" Version="1.9.*" />
<PackageReference Include="OpenTelemetry.Exporter.Prometheus.AspNetCore" Version="1.9.*" />

<!-- Instrumentation -->
<PackageReference Include="OpenTelemetry.Instrumentation.AspNetCore" Version="1.9.*" />
<PackageReference Include="OpenTelemetry.Instrumentation.Http" Version="1.9.*" />
<PackageReference Include="Npgsql.OpenTelemetry" Version="8.*" />
<PackageReference Include="OpenTelemetry.Instrumentation.StackExchangeRedis" Version="1.9.*" />

<!-- Logging -->
<PackageReference Include="Serilog.AspNetCore" Version="8.*" />
<PackageReference Include="Serilog.Sinks.OpenTelemetry" Version="4.*" />
<PackageReference Include="Serilog.Sinks.Seq" Version="8.*" />
```

#### OpenTelemetry Configuration

```csharp
// Program.cs - Complete OpenTelemetry Setup
var builder = WebApplication.CreateBuilder(args);

// Service name for all telemetry
var serviceName = "IdP.Api";
var serviceVersion = Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "1.0.0";

// Configure OpenTelemetry
builder.Services.AddOpenTelemetry()
    .ConfigureResource(resource => resource
        .AddService(
            serviceName: serviceName,
            serviceVersion: serviceVersion,
            serviceInstanceId: Environment.MachineName)
        .AddAttributes(new Dictionary<string, object>
        {
            ["deployment.environment"] = builder.Environment.EnvironmentName,
            ["service.namespace"] = "pqc-identity"
        }))
    .WithTracing(tracing => tracing
        // Instrumentation
        .AddAspNetCoreInstrumentation(options =>
        {
            options.RecordException = true;
            options.Filter = httpContext =>
                !httpContext.Request.Path.StartsWithSegments("/health") &&
                !httpContext.Request.Path.StartsWithSegments("/metrics");
        })
        .AddHttpClientInstrumentation(options =>
        {
            options.RecordException = true;
        })
        .AddNpgsql()
        .AddRedisInstrumentation()
        // Custom instrumentation source
        .AddSource("IdP.Api")
        .AddSource("IdP.Identity")
        .AddSource("IdP.Certificate")
        .AddSource("IdP.Crypto")
        // Exporter
        .AddOtlpExporter(options =>
        {
            options.Endpoint = new Uri(builder.Configuration["Otlp:Endpoint"] ?? "http://localhost:4317");
            options.Protocol = OtlpExportProtocol.Grpc;
        }))
    .WithMetrics(metrics => metrics
        // Instrumentation
        .AddAspNetCoreInstrumentation()
        .AddHttpClientInstrumentation()
        .AddRuntimeInstrumentation()
        .AddProcessInstrumentation()
        // Custom meters
        .AddMeter("IdP.Api")
        .AddMeter("IdP.Identity")
        .AddMeter("IdP.Certificate")
        // Prometheus exporter
        .AddPrometheusExporter());

// Configure Serilog with OpenTelemetry
builder.Host.UseSerilog((context, services, configuration) => configuration
    .ReadFrom.Configuration(context.Configuration)
    .ReadFrom.Services(services)
    .Enrich.FromLogContext()
    .Enrich.WithMachineName()
    .Enrich.WithEnvironmentName()
    .Enrich.WithProperty("ServiceName", serviceName)
    .WriteTo.Console(outputTemplate:
        "[{Timestamp:HH:mm:ss} {Level:u3}] {Message:lj} {Properties:j}{NewLine}{Exception}")
    .WriteTo.OpenTelemetry(options =>
    {
        options.Endpoint = builder.Configuration["Otlp:Endpoint"] ?? "http://localhost:4317";
        options.Protocol = OtlpProtocol.Grpc;
        options.ResourceAttributes = new Dictionary<string, object>
        {
            ["service.name"] = serviceName
        };
    })
    .WriteTo.Seq(builder.Configuration["Seq:Url"] ?? "http://localhost:5341"));

var app = builder.Build();

// Prometheus metrics endpoint
app.MapPrometheusScrapingEndpoint("/metrics");

// Health checks
app.MapHealthChecks("/health");
```

#### Custom Instrumentation

```csharp
// Custom ActivitySource for distributed tracing
public static class Telemetry
{
    public static readonly ActivitySource ActivitySource = new("IdP.Api", "1.0.0");

    // Custom metrics
    public static readonly Meter Meter = new("IdP.Api", "1.0.0");

    // Counters
    public static readonly Counter<long> AuthenticationAttempts =
        Meter.CreateCounter<long>("idp.authentication.attempts", "count",
            "Number of authentication attempts");

    public static readonly Counter<long> CertificatesIssued =
        Meter.CreateCounter<long>("idp.certificates.issued", "count",
            "Number of certificates issued");

    // Histograms
    public static readonly Histogram<double> AuthenticationDuration =
        Meter.CreateHistogram<double>("idp.authentication.duration", "ms",
            "Duration of authentication operations");

    public static readonly Histogram<double> CertificateIssuanceDuration =
        Meter.CreateHistogram<double>("idp.certificate.issuance.duration", "ms",
            "Duration of certificate issuance");

    // Gauges (via ObservableGauge)
    public static readonly ObservableGauge<int> ActiveSessions;

    static Telemetry()
    {
        ActiveSessions = Meter.CreateObservableGauge(
            "idp.sessions.active",
            () => SessionStore.GetActiveCount(),
            "sessions",
            "Number of active sessions");
    }
}

// Usage in handlers
public class AuthenticateUserHandler : ICommandHandler<AuthenticateUserCommand, AuthResult>
{
    private readonly ILogger<AuthenticateUserHandler> _logger;

    public async Task<Result<AuthResult>> HandleAsync(
        AuthenticateUserCommand command,
        CancellationToken ct = default)
    {
        using var activity = Telemetry.ActivitySource.StartActivity(
            "AuthenticateUser",
            ActivityKind.Internal);

        activity?.SetTag("user.email", command.Email);
        activity?.SetTag("auth.method", command.Method.ToString());

        var stopwatch = Stopwatch.StartNew();

        try
        {
            // Authentication logic...
            var result = await AuthenticateAsync(command, ct);

            activity?.SetTag("auth.success", result.IsSuccess);

            Telemetry.AuthenticationAttempts.Add(1,
                new KeyValuePair<string, object?>("success", result.IsSuccess),
                new KeyValuePair<string, object?>("method", command.Method.ToString()));

            if (result.IsSuccess)
            {
                _logger.LogInformation(
                    "User {Email} authenticated successfully via {Method}",
                    command.Email, command.Method);
            }
            else
            {
                _logger.LogWarning(
                    "Authentication failed for {Email}: {Error}",
                    command.Email, result.Error?.Message);
            }

            return result;
        }
        catch (Exception ex)
        {
            activity?.SetStatus(ActivityStatusCode.Error, ex.Message);
            activity?.RecordException(ex);

            _logger.LogError(ex, "Authentication error for {Email}", command.Email);
            throw;
        }
        finally
        {
            stopwatch.Stop();
            Telemetry.AuthenticationDuration.Record(
                stopwatch.ElapsedMilliseconds,
                new KeyValuePair<string, object?>("method", command.Method.ToString()));
        }
    }
}
```

#### Trace Context Propagation

```csharp
// Middleware to extract/inject trace context
public class TraceContextMiddleware
{
    private readonly RequestDelegate _next;

    public async Task InvokeAsync(HttpContext context)
    {
        // Activity is automatically created by ASP.NET Core instrumentation
        var activity = Activity.Current;

        // Add custom baggage for multi-tenant context
        if (context.Request.Headers.TryGetValue("X-Tenant-Id", out var tenantId))
        {
            activity?.SetBaggage("tenant.id", tenantId);
            activity?.SetTag("tenant.id", tenantId.ToString());
        }

        // Add trace ID to response headers for debugging
        if (activity != null)
        {
            context.Response.Headers["X-Trace-Id"] = activity.TraceId.ToString();
        }

        await _next(context);
    }
}
```

#### Development Environment (docker-compose)

```yaml
# docker-compose.observability.yml
version: '3.8'

services:
  # Jaeger - Distributed Tracing
  jaeger:
    image: jaegertracing/all-in-one:1.53
    container_name: idp-jaeger
    ports:
      - "6831:6831/udp"   # Thrift compact
      - "4317:4317"       # OTLP gRPC
      - "4318:4318"       # OTLP HTTP
      - "16686:16686"     # UI
    environment:
      - COLLECTOR_OTLP_ENABLED=true

  # Prometheus - Metrics
  prometheus:
    image: prom/prometheus:v2.48.0
    container_name: idp-prometheus
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus-data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.enable-lifecycle'

  # Grafana - Dashboards
  grafana:
    image: grafana/grafana:10.2.0
    container_name: idp-grafana
    ports:
      - "3000:3000"
    volumes:
      - grafana-data:/var/lib/grafana
      - ./grafana/provisioning:/etc/grafana/provisioning
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
      - GF_USERS_ALLOW_SIGN_UP=false

  # Seq - Structured Logging
  seq:
    image: datalust/seq:2023.4
    container_name: idp-seq
    ports:
      - "5341:80"     # Ingestion
      - "8081:80"     # UI (mapped to 8081 to avoid conflicts)
    environment:
      - ACCEPT_EULA=Y
    volumes:
      - seq-data:/data

volumes:
  prometheus-data:
  grafana-data:
  seq-data:
```

#### Prometheus Configuration

```yaml
# prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'idp-api'
    static_configs:
      - targets: ['host.docker.internal:5000']
    metrics_path: /metrics
    scheme: http

  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']
```

#### appsettings.json Configuration

```json
{
  "Otlp": {
    "Endpoint": "http://localhost:4317"
  },
  "Seq": {
    "Url": "http://localhost:5341"
  },
  "Serilog": {
    "MinimumLevel": {
      "Default": "Information",
      "Override": {
        "Microsoft.AspNetCore": "Warning",
        "Microsoft.EntityFrameworkCore": "Warning",
        "System.Net.Http.HttpClient": "Warning"
      }
    }
  }
}
```

#### Observability Endpoints

| Service | Development URL | Purpose |
|---------|-----------------|---------|
| Jaeger UI | http://localhost:16686 | Trace visualization |
| Prometheus | http://localhost:9090 | Metrics queries |
| Grafana | http://localhost:3000 | Dashboards |
| Seq | http://localhost:8081 | Log search |
| API Metrics | http://localhost:5000/metrics | Prometheus scrape endpoint |
| API Health | http://localhost:5000/health | Health check |

### Backend Modules

#### 1. Identity Module

Handles authentication and authorization:

- OIDC/OAuth 2.0 endpoints
- FIDO2/WebAuthn registration and authentication
- PQC-JWT token issuance and validation
- Session management
- User authentication flows

#### 2. Certificate Module

Private CA functionality:

- CSR (Certificate Signing Request) processing
- Certificate issuance with PQC signatures
- Certificate renewal
- Certificate revocation (CRL)
- Certificate chain management

#### 3. Admin Module

Administrative functions:

- Tenant/Organization management
- User management
- Relying Party (RP) registration
- Policy management
- Audit logging

#### 4. Crypto Module

PQC abstraction layer:

- ICryptoProvider interface
- ML-DSA provider (.NET 10 native)
- KAZ-SIGN provider (P/Invoke)
- PQC-JWT service
- Key Vault integration

---

## Client Applications

### Client Architecture Pattern

All native clients follow MVVM pattern:

```
App/
├── Features/
│   ├── Login/
│   │   ├── LoginView
│   │   └── LoginViewModel
│   ├── Dashboard/
│   ├── Certificate/
│   ├── Auth/                       # QR scanning, biometrics
│   └── Settings/
│
├── Core/
│   ├── Network/
│   │   ├── APIClient
│   │   ├── Endpoints
│   │   └── Models/
│   ├── Crypto/
│   │   ├── KazSignWrapper
│   │   └── CsrBuilder
│   └── Storage/
│       ├── SecureStorage
│       └── KeychainManager
│
└── Resources/
```

### Platform-Specific Crypto Integration

#### Android (Kotlin + JNI)

```kotlin
class KazSign private constructor(private val level: SecurityLevel) : AutoCloseable {
    companion object {
        init { System.loadLibrary("kazsign") }
    }

    private external fun nativeInit(level: Int): Int
    private external fun nativeGenerateKeyPair(pk: ByteArray, sk: ByteArray): Int
    private external fun nativeSign(sig: ByteArray, msg: ByteArray, sk: ByteArray): Long
    private external fun nativeVerify(msg: ByteArray, sig: ByteArray, pk: ByteArray): Int
    private external fun nativeClear(level: Int)

    // ... implementation
}
```

#### iOS/macOS (Swift)

```swift
import KazSignNative  // XCFramework

final class KazSignManager {
    private let level: SecurityLevel

    init(level: SecurityLevel) throws {
        let result = kaz_sign_init_level(level.rawValue)
        guard result == 0 else { throw KazSignError.initFailed(result) }
    }

    func generateKeyPair() throws -> KeyPair { ... }
    func sign(message: Data, secretKey: Data) throws -> Data { ... }
    func verify(message: Data, signature: Data, publicKey: Data) -> Bool { ... }
}
```

#### Windows (C# P/Invoke)

```csharp
public sealed class KazSignWrapper : IDisposable
{
    private readonly SecurityLevel _level;

    public KazSignWrapper(SecurityLevel level) {
        int result = KazSignNative.kaz_sign_init_level((int)level);
        if (result != 0) throw new CryptographicException($"Init failed: {result}");
    }

    public KeyPair GenerateKeyPair() { ... }
    public byte[] Sign(byte[] message, byte[] secretKey) { ... }
    public bool Verify(byte[] message, byte[] signature, byte[] publicKey) { ... }
}
```

---

## Cryptographic Architecture

### Crypto Provider Interface

```csharp
public interface ICryptoProvider : IDisposable
{
    PqcAlgorithm Algorithm { get; }

    // Key management
    KeyPairResult GenerateKeyPair();
    byte[] ExportPublicKey();
    byte[] ExportPrivateKey();
    void ImportKeyPair(byte[] publicKey, byte[] privateKey);

    // Signing
    byte[] Sign(byte[] data);
    bool Verify(byte[] data, byte[] signature, byte[] publicKey);

    // Metadata
    int PublicKeySize { get; }
    int PrivateKeySize { get; }
    int SignatureSize { get; }
}
```

### Algorithm Parameters

#### ML-DSA (Dilithium)

| Level | Public Key | Private Key | Signature |
|-------|------------|-------------|-----------|
| ML-DSA-44 | 1,312 bytes | 2,560 bytes | 2,420 bytes |
| ML-DSA-65 | 1,952 bytes | 4,032 bytes | 3,309 bytes |
| ML-DSA-87 | 2,592 bytes | 4,896 bytes | 4,627 bytes |

#### KAZ-SIGN

| Level | Public Key | Private Key | Signature Overhead |
|-------|------------|-------------|-------------------|
| KAZ-SIGN-128 | 54 bytes | 32 bytes | 162 bytes |
| KAZ-SIGN-192 | 88 bytes | 50 bytes | 264 bytes |
| KAZ-SIGN-256 | 118 bytes | 64 bytes | 356 bytes |

### PQC-JWT Structure

```
Header:
{
  "alg": "ML-DSA-65" | "KAZ-SIGN-128" | ...,
  "typ": "JWT",
  "kid": "<key-id>"
}

Payload:
{
  "iss": "https://idp.example.com/tenant-slug",
  "sub": "<user-id>",
  "aud": "<client-id>",
  "iat": <issued-at>,
  "exp": <expiration>,
  "jti": "<unique-token-id>",
  // ... additional claims
}

Signature:
  PQC_SIGN(base64url(header) + "." + base64url(payload), private_key)
```

---

## Authentication Flows

### Supported Protocols

| Protocol | Purpose |
|----------|---------|
| OIDC/OAuth 2.0 | Web/API authentication |
| FIDO2/WebAuthn | Passwordless authentication |
| PQC Certificate | Certificate-based authentication |

### OIDC Endpoints

| Endpoint | Path |
|----------|------|
| Discovery | `/.well-known/openid-configuration` |
| JWKS | `/.well-known/jwks.json` |
| Authorization | `/{tenant}/oauth/authorize` |
| Token | `/{tenant}/oauth/token` |
| UserInfo | `/{tenant}/oauth/userinfo` |
| Revocation | `/{tenant}/oauth/revoke` |

### Grant Types Supported

- Authorization Code (with PKCE)
- Refresh Token
- Client Credentials

---

## Certificate Management

### Private CA Hierarchy

```
┌─────────────────────────────────────┐
│           Platform Root CA           │
│         (Offline, HSM-backed)        │
└─────────────────┬───────────────────┘
                  │
    ┌─────────────┼─────────────┐
    │             │             │
    ▼             ▼             ▼
┌────────┐  ┌────────┐  ┌────────┐
│Tenant A│  │Tenant B│  │Tenant C│
│Issue CA│  │Issue CA│  │Issue CA│
└───┬────┘  └───┬────┘  └───┬────┘
    │           │           │
    ▼           ▼           ▼
┌────────┐  ┌────────┐  ┌────────┐
│End User│  │End User│  │End User│
│ Certs  │  │ Certs  │  │ Certs  │
└────────┘  └────────┘  └────────┘
```

### Certificate Workflow

1. **CSR Generation** (Client-side)
   - Generate PQC key pair on device
   - Create CSR with subject info
   - Sign CSR with private key
   - Send CSR to backend

2. **Certificate Issuance** (Backend)
   - Verify CSR signature
   - Validate user identity
   - Issue certificate signed by Tenant CA
   - Return certificate to client

3. **Certificate Storage** (Client-side)
   - Store certificate in secure storage
   - Store private key in hardware-backed keystore

---

## Multi-Tenancy

### Tenant Resolution

Tenants are resolved via:

1. **HTTP Header**: `X-Tenant-Id`
2. **Route Parameter**: `/{tenantSlug}/...`
3. **Subdomain**: `{tenant}.platform.com`

### Tenant Isolation

- Database-level: Global query filters
- Key Vault: Per-tenant key isolation
- Certificates: Per-tenant CA

### Tenant Configuration

```csharp
public class Tenant
{
    public Guid Id { get; set; }
    public string Name { get; set; }
    public string Slug { get; set; }
    public TenantType Type { get; set; }           // SaaS | OnPremise
    public PqcAlgorithm PrimaryAlgorithm { get; set; }
    public byte[] CaCertificate { get; set; }
    public string CaKeyId { get; set; }            // Key Vault reference
    public TenantSettings Settings { get; set; }
}

public class TenantSettings
{
    public int CertificateValidityDays { get; set; } = 365;
    public int JwtAccessTokenLifetimeMinutes { get; set; } = 15;
    public int JwtRefreshTokenLifetimeDays { get; set; } = 30;
    public bool RequireFido2 { get; set; } = false;
    public bool AllowPasswordAuth { get; set; } = true;
}
```

---

## Deployment Models

### SaaS Deployment

```
┌─────────────────────────────────────────┐
│            Load Balancer                 │
└─────────────────┬───────────────────────┘
                  │
    ┌─────────────┼─────────────┐
    │             │             │
    ▼             ▼             ▼
┌────────┐  ┌────────┐  ┌────────┐
│  API   │  │  API   │  │  API   │
│ Pod 1  │  │ Pod 2  │  │ Pod 3  │
└───┬────┘  └───┬────┘  └───┬────┘
    │           │           │
    └─────────┬─┴───────────┘
              │
              ▼
┌─────────────────────────────────────────┐
│         Shared Infrastructure            │
│  PostgreSQL │ Redis │ Azure Key Vault   │
└─────────────────────────────────────────┘
```

### On-Premise Deployment

```
┌─────────────────────────────────────────┐
│         Customer Infrastructure          │
│                                         │
│  ┌─────────────────────────────────┐   │
│  │      Docker Compose / K8s       │   │
│  │                                 │   │
│  │  ┌─────────┐  ┌─────────────┐  │   │
│  │  │   API   │  │  PostgreSQL │  │   │
│  │  └─────────┘  └─────────────┘  │   │
│  │  ┌─────────┐  ┌─────────────┐  │   │
│  │  │  Redis  │  │  Local HSM  │  │   │
│  │  └─────────┘  └─────────────┘  │   │
│  └─────────────────────────────────┘   │
└─────────────────────────────────────────┘
```

---

## Folder Structure

```
PqcIdentityPlatform/
│
├── src/
│   │
│   ├── Backend/                                   # All C# Backend Code
│   │   │
│   │   ├── PqcIdentity.Api/                       # API Host
│   │   │   ├── Program.cs
│   │   │   ├── appsettings.json
│   │   │   ├── appsettings.Development.json
│   │   │   └── appsettings.OnPremise.json
│   │   │
│   │   ├── Modules/
│   │   │   ├── Identity/                          # OIDC/OAuth/FIDO2/JWT
│   │   │   │   ├── PqcIdentity.Identity.Api/
│   │   │   │   ├── PqcIdentity.Identity.Application/
│   │   │   │   ├── PqcIdentity.Identity.Domain/
│   │   │   │   └── PqcIdentity.Identity.Infrastructure/
│   │   │   │
│   │   │   ├── Certificate/                       # Private CA
│   │   │   │   ├── PqcIdentity.Certificate.Api/
│   │   │   │   ├── PqcIdentity.Certificate.Application/
│   │   │   │   ├── PqcIdentity.Certificate.Domain/
│   │   │   │   └── PqcIdentity.Certificate.Infrastructure/
│   │   │   │
│   │   │   ├── Admin/                             # Admin Management
│   │   │   │   ├── PqcIdentity.Admin.Api/
│   │   │   │   ├── PqcIdentity.Admin.Application/
│   │   │   │   ├── PqcIdentity.Admin.Domain/
│   │   │   │   └── PqcIdentity.Admin.Infrastructure/
│   │   │   │
│   │   │   └── Crypto/                            # PQC Abstraction
│   │   │       ├── PqcIdentity.Crypto.Api/
│   │   │       ├── PqcIdentity.Crypto.Application/
│   │   │       ├── PqcIdentity.Crypto.Domain/
│   │   │       └── PqcIdentity.Crypto.Infrastructure/
│   │   │           ├── Providers/
│   │   │           │   ├── MLDsaCryptoProvider.cs
│   │   │           │   └── KazSignCryptoProvider.cs
│   │   │           └── Native/
│   │   │               ├── KazSignNative.cs
│   │   │               └── runtimes/
│   │   │
│   │   └── Shared/
│   │       ├── PqcIdentity.SharedKernel/
│   │       ├── PqcIdentity.SharedKernel.Infrastructure/
│   │       └── PqcIdentity.Common/
│   │
│   ├── Web/                                       # C# Blazor Web Apps
│   │   ├── PqcIdentity.AdminPortal/
│   │   └── PqcIdentity.UserPortal/
│   │
│   ├── Clients/                                   # Native Client Applications
│   │   ├── Android/                               # Kotlin
│   │   │   ├── app/
│   │   │   └── kazsign/                           # KAZ-SIGN Android Library
│   │   │
│   │   ├── iOS/                                   # Swift
│   │   │   ├── PqcIdentity/
│   │   │   └── Frameworks/KazSignNative.xcframework
│   │   │
│   │   ├── macOS/                                 # Swift
│   │   │   ├── PqcIdentityMac/
│   │   │   └── Frameworks/KazSignNative.xcframework
│   │   │
│   │   ├── Windows/                               # C# WinUI 3
│   │   │   ├── PqcIdentity.Windows/
│   │   │   └── PqcIdentity.Windows.Core/
│   │   │
│   │   └── Shared/
│   │       └── PqcIdentity.Contracts/             # Shared API DTOs
│   │
│   └── Sdk/                                       # SDK for Relying Parties
│       ├── DotNet/
│       │   ├── PqcIdentity.Sdk/
│       │   └── PqcIdentity.Sdk.AspNetCore/
│       ├── Kotlin/
│       │   └── pqcidentity-sdk/
│       └── Swift/
│           └── PqcIdentitySdk/
│
├── libs/                                          # Native PQC Libraries Source
│   ├── kazsign/
│   │   ├── include/kaz/
│   │   ├── src/internal/
│   │   ├── bindings/
│   │   │   ├── android/
│   │   │   ├── apple/
│   │   │   └── windows/
│   │   └── Makefile
│   │
│   └── kazkem/
│
├── tests/
│   ├── Backend/
│   │   ├── Unit/
│   │   ├── Integration/
│   │   └── E2E/
│   ├── Clients/
│   │   ├── Android/
│   │   ├── iOS/
│   │   └── Windows/
│   └── Sdk/
│
├── deploy/
│   ├── docker/
│   ├── kubernetes/
│   ├── terraform/
│   └── scripts/
│
├── docs/
│   ├── architecture/
│   ├── api/
│   ├── sdk/
│   ├── deployment/
│   └── clients/
│
├── tools/
│   ├── openapi-generator/
│   └── native-lib-builder/
│
├── .github/workflows/
│
├── PqcIdentityPlatform.sln
├── Directory.Build.props
├── Directory.Packages.props
├── README.md
├── ARCHITECTURE.md                                # This file
└── CLAUDE.md
```

---

## API Design

### REST API Conventions

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/v1/resource` | List resources |
| GET | `/api/v1/resource/{id}` | Get single resource |
| POST | `/api/v1/resource` | Create resource |
| PUT | `/api/v1/resource/{id}` | Update resource |
| DELETE | `/api/v1/resource/{id}` | Delete resource |

### API Versioning

- URL path versioning: `/api/v1/...`
- Header versioning: `Api-Version: 1.0`

### Response Format

```json
{
  "success": true,
  "data": { ... },
  "error": null,
  "traceId": "abc123"
}
```

### Error Response

```json
{
  "success": false,
  "data": null,
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid request",
    "details": [
      { "field": "email", "message": "Invalid email format" }
    ]
  },
  "traceId": "abc123"
}
```

---

## Security Considerations

### Key Management

- CA private keys stored in HSM or Key Vault
- User private keys stored in device secure enclave
- Key rotation policies enforced

### Transport Security

- TLS 1.3 required
- Certificate pinning for mobile apps
- HSTS enabled

### Authentication Security

- PKCE required for authorization code flow
- Refresh token rotation
- Short-lived access tokens (15 min default)

### Audit Logging

All security events logged:
- Authentication attempts
- Certificate issuance/revocation
- Administrative actions
- API access

### Compliance Considerations

- GDPR data handling
- SOC 2 audit trails
- NIST PQC standards compliance

---

## HSM Integration

### Overview

The platform requires Hardware Security Module (HSM) integration for:
- **Platform Root CA Key** - Master signing key for the entire platform
- **Tenant/Organization CA Keys** - Per-organization signing keys
- **JWT Signing Keys** - PQC keys for token signing

### HSM Abstraction Layer

The platform uses an abstraction layer to support multiple HSM backends:

```csharp
public interface IHsmService
{
    // Key Operations
    Task<HsmKeyInfo> GenerateKeyAsync(KeyGenerationRequest request, CancellationToken ct = default);
    Task<byte[]> SignAsync(string keyId, byte[] data, SignatureAlgorithm algorithm, CancellationToken ct = default);
    Task<bool> VerifyAsync(string keyId, byte[] data, byte[] signature, SignatureAlgorithm algorithm, CancellationToken ct = default);
    Task<byte[]> ExportPublicKeyAsync(string keyId, CancellationToken ct = default);
    Task DeleteKeyAsync(string keyId, CancellationToken ct = default);

    // Key Info
    Task<HsmKeyInfo?> GetKeyInfoAsync(string keyId, CancellationToken ct = default);
    Task<IReadOnlyList<HsmKeyInfo>> ListKeysAsync(string? prefix = null, CancellationToken ct = default);

    // Key Rotation
    Task<KeyRotationResult> RotateKeyAsync(string keyId, KeyRotationPolicy policy, CancellationToken ct = default);
    Task<IReadOnlyList<KeyVersion>> GetKeyVersionsAsync(string keyId, CancellationToken ct = default);

    // Health
    Task<HsmHealthStatus> GetHealthAsync(CancellationToken ct = default);
}

public record HsmKeyInfo(
    string KeyId,
    string KeyName,
    KeyType KeyType,
    SignatureAlgorithm Algorithm,
    DateTime CreatedAt,
    DateTime? ExpiresAt,
    string? CurrentVersion,
    bool IsEnabled,
    Dictionary<string, string> Tags
);

public record KeyGenerationRequest(
    string KeyName,
    KeyType KeyType,
    SignatureAlgorithm Algorithm,
    KeyRotationPolicy? RotationPolicy = null,
    Dictionary<string, string>? Tags = null
);

public record KeyRotationPolicy(
    bool AutoRotate,
    TimeSpan RotationInterval,
    int MaxVersionsToRetain,
    TimeSpan GracePeriodAfterRotation
);

public record KeyRotationResult(
    string KeyId,
    string OldVersion,
    string NewVersion,
    DateTime RotatedAt
);

public record KeyVersion(
    string Version,
    DateTime CreatedAt,
    DateTime? DisabledAt,
    bool IsCurrent
);

public enum KeyType
{
    RootCa,
    TenantCa,
    JwtSigning,
    DataEncryption
}

public enum SignatureAlgorithm
{
    // ML-DSA (Dilithium) - .NET 10 Native
    MlDsa44,
    MlDsa65,
    MlDsa87,

    // KAZ-SIGN - Custom Native Library
    KazSign128,
    KazSign192,
    KazSign256
}
```

### Supported HSM Providers

#### 1. Azure Key Vault (Cloud)

```csharp
public class AzureKeyVaultHsmService : IHsmService
{
    private readonly SecretClient _secretClient;
    private readonly KeyClient _keyClient;
    private readonly CryptographyClient _cryptoClient;

    public AzureKeyVaultHsmService(AzureKeyVaultOptions options)
    {
        var credential = new DefaultAzureCredential();
        var vaultUri = new Uri(options.VaultUri);

        _secretClient = new SecretClient(vaultUri, credential);
        _keyClient = new KeyClient(vaultUri, credential);
    }

    // Note: Azure Key Vault doesn't natively support PQC algorithms yet
    // For PQC, the private key material is stored encrypted in Key Vault
    // and signing operations happen in application memory

    public async Task<byte[]> SignAsync(string keyId, byte[] data, SignatureAlgorithm algorithm, CancellationToken ct)
    {
        // For PQC algorithms, retrieve encrypted key and sign in-memory
        if (IsPqcAlgorithm(algorithm))
        {
            var encryptedKey = await GetEncryptedKeyAsync(keyId, ct);
            var privateKey = await DecryptKeyMaterialAsync(encryptedKey, ct);
            try
            {
                return SignWithPqc(data, privateKey, algorithm);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(privateKey);
            }
        }

        // For classical algorithms, use native Key Vault signing
        var cryptoClient = new CryptographyClient(new Uri($"{_vaultUri}/keys/{keyId}"), _credential);
        var result = await cryptoClient.SignDataAsync(MapAlgorithm(algorithm), data, ct);
        return result.Signature;
    }
}
```

#### 2. PKCS#11 (Hardware HSM)

```csharp
public class Pkcs11HsmService : IHsmService, IDisposable
{
    private readonly Pkcs11InteropFactory _factory;
    private readonly ISlot _slot;
    private readonly ISession _session;

    public Pkcs11HsmService(Pkcs11Options options)
    {
        _factory = new Pkcs11InteropFactory();
        var library = _factory.LoadPkcs11Library(options.LibraryPath);
        _slot = library.GetSlotList(SlotsType.WithTokenPresent)
            .First(s => s.GetTokenInfo().Label == options.TokenLabel);
        _session = _slot.OpenSession(SessionType.ReadWrite);
        _session.Login(CKU.CKU_USER, options.Pin);
    }

    public async Task<HsmKeyInfo> GenerateKeyAsync(KeyGenerationRequest request, CancellationToken ct)
    {
        // PKCS#11 key generation attributes
        var publicKeyAttributes = new List<IObjectAttribute>
        {
            _factory.CreateObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY),
            _factory.CreateObjectAttribute(CKA.CKA_TOKEN, true),
            _factory.CreateObjectAttribute(CKA.CKA_LABEL, request.KeyName),
            _factory.CreateObjectAttribute(CKA.CKA_VERIFY, true),
        };

        var privateKeyAttributes = new List<IObjectAttribute>
        {
            _factory.CreateObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
            _factory.CreateObjectAttribute(CKA.CKA_TOKEN, true),
            _factory.CreateObjectAttribute(CKA.CKA_LABEL, request.KeyName),
            _factory.CreateObjectAttribute(CKA.CKA_SIGN, true),
            _factory.CreateObjectAttribute(CKA.CKA_SENSITIVE, true),
            _factory.CreateObjectAttribute(CKA.CKA_EXTRACTABLE, false),
        };

        // Generate key pair
        _session.GenerateKeyPair(
            GetMechanismForAlgorithm(request.Algorithm),
            publicKeyAttributes,
            privateKeyAttributes,
            out var publicKeyHandle,
            out var privateKeyHandle
        );

        return new HsmKeyInfo(
            KeyId: GetKeyId(publicKeyHandle),
            KeyName: request.KeyName,
            KeyType: request.KeyType,
            Algorithm: request.Algorithm,
            CreatedAt: DateTime.UtcNow,
            ExpiresAt: null,
            CurrentVersion: "1",
            IsEnabled: true,
            Tags: request.Tags ?? new()
        );
    }

    public void Dispose()
    {
        _session?.Logout();
        _session?.Dispose();
    }
}
```

#### 3. HashiCorp Vault (Cloud/On-Premise)

```csharp
public class HashiCorpVaultHsmService : IHsmService
{
    private readonly VaultClient _client;
    private readonly string _transitMountPoint;

    public HashiCorpVaultHsmService(HashiCorpVaultOptions options)
    {
        var settings = new VaultClientSettings(options.Address, new TokenAuthMethodInfo(options.Token));
        _client = new VaultClient(settings);
        _transitMountPoint = options.TransitMountPoint ?? "transit";
    }

    public async Task<HsmKeyInfo> GenerateKeyAsync(KeyGenerationRequest request, CancellationToken ct)
    {
        // Create key in Vault Transit secrets engine
        await _client.V1.Secrets.Transit.CreateKeyAsync(
            request.KeyName,
            new CreateKeyRequestOptions
            {
                Type = MapToVaultKeyType(request.Algorithm),
                Exportable = false,
                AllowPlaintextBackup = false
            },
            _transitMountPoint
        );

        var keyInfo = await _client.V1.Secrets.Transit.ReadKeyAsync(request.KeyName, _transitMountPoint);

        return new HsmKeyInfo(
            KeyId: request.KeyName,
            KeyName: request.KeyName,
            KeyType: request.KeyType,
            Algorithm: request.Algorithm,
            CreatedAt: DateTime.UtcNow,
            ExpiresAt: null,
            CurrentVersion: keyInfo.Data.LatestVersion.ToString(),
            IsEnabled: true,
            Tags: request.Tags ?? new()
        );
    }

    public async Task<KeyRotationResult> RotateKeyAsync(string keyId, KeyRotationPolicy policy, CancellationToken ct)
    {
        var beforeRotation = await _client.V1.Secrets.Transit.ReadKeyAsync(keyId, _transitMountPoint);
        var oldVersion = beforeRotation.Data.LatestVersion.ToString();

        await _client.V1.Secrets.Transit.RotateKeyAsync(keyId, _transitMountPoint);

        var afterRotation = await _client.V1.Secrets.Transit.ReadKeyAsync(keyId, _transitMountPoint);
        var newVersion = afterRotation.Data.LatestVersion.ToString();

        // Trim old versions if needed
        if (policy.MaxVersionsToRetain > 0)
        {
            var minVersion = afterRotation.Data.LatestVersion - policy.MaxVersionsToRetain;
            if (minVersion > 0)
            {
                await _client.V1.Secrets.Transit.TrimKeyAsync(keyId, minVersion, _transitMountPoint);
            }
        }

        return new KeyRotationResult(keyId, oldVersion, newVersion, DateTime.UtcNow);
    }
}
```

### Key Rotation Management

#### Rotation Policies (Based on NIST SP 800-57)

```csharp
public static class KeyRotationPolicies
{
    /// <summary>
    /// Platform Root CA Key - 10 year validity, manual rotation only
    /// </summary>
    public static KeyRotationPolicy RootCaKey => new(
        AutoRotate: false,
        RotationInterval: TimeSpan.FromDays(3650),  // 10 years
        MaxVersionsToRetain: 2,
        GracePeriodAfterRotation: TimeSpan.FromDays(365)
    );

    /// <summary>
    /// Tenant/Organization CA Key - 3 year validity, manual rotation
    /// </summary>
    public static KeyRotationPolicy TenantCaKey => new(
        AutoRotate: false,
        RotationInterval: TimeSpan.FromDays(1095),  // 3 years
        MaxVersionsToRetain: 3,
        GracePeriodAfterRotation: TimeSpan.FromDays(180)
    );

    /// <summary>
    /// JWT Signing Key - 90 day rotation, automatic
    /// </summary>
    public static KeyRotationPolicy JwtSigningKey => new(
        AutoRotate: true,
        RotationInterval: TimeSpan.FromDays(90),
        MaxVersionsToRetain: 3,
        GracePeriodAfterRotation: TimeSpan.FromDays(30)
    );

    /// <summary>
    /// Data Encryption Key - 1 year rotation, automatic
    /// </summary>
    public static KeyRotationPolicy DataEncryptionKey => new(
        AutoRotate: true,
        RotationInterval: TimeSpan.FromDays(365),
        MaxVersionsToRetain: 5,
        GracePeriodAfterRotation: TimeSpan.FromDays(90)
    );
}
```

#### Key Rotation Service

```csharp
public class KeyRotationService : IKeyRotationService
{
    private readonly IHsmService _hsmService;
    private readonly IKeyMetadataRepository _keyMetadataRepository;
    private readonly ILogger<KeyRotationService> _logger;

    public async Task<KeyRotationResult> RotateKeyAsync(string keyId, CancellationToken ct = default)
    {
        var keyMetadata = await _keyMetadataRepository.GetAsync(keyId, ct)
            ?? throw new KeyNotFoundException(keyId);

        var policy = GetPolicyForKeyType(keyMetadata.KeyType);

        _logger.LogInformation("Rotating key {KeyId} with policy {@Policy}", keyId, policy);

        // Perform rotation in HSM
        var result = await _hsmService.RotateKeyAsync(keyId, policy, ct);

        // Update metadata
        keyMetadata.CurrentVersion = result.NewVersion;
        keyMetadata.LastRotatedAt = result.RotatedAt;
        keyMetadata.NextRotationAt = result.RotatedAt + policy.RotationInterval;

        await _keyMetadataRepository.UpdateAsync(keyMetadata, ct);

        _logger.LogInformation(
            "Key {KeyId} rotated from version {OldVersion} to {NewVersion}",
            keyId, result.OldVersion, result.NewVersion
        );

        return result;
    }

    public async Task CheckAndRotateDueKeysAsync(CancellationToken ct = default)
    {
        var dueKeys = await _keyMetadataRepository.GetKeysDueForRotationAsync(ct);

        foreach (var key in dueKeys)
        {
            if (!GetPolicyForKeyType(key.KeyType).AutoRotate)
            {
                _logger.LogWarning(
                    "Key {KeyId} is due for rotation but auto-rotate is disabled. Manual rotation required.",
                    key.KeyId
                );
                continue;
            }

            try
            {
                await RotateKeyAsync(key.KeyId, ct);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to rotate key {KeyId}", key.KeyId);
            }
        }
    }
}
```

### Key Naming Convention

```
{environment}/{tenant-id}/{key-type}/{algorithm}/{purpose}

Examples:
- prod/platform/root-ca/ml-dsa-65/signing
- prod/tenant-abc123/tenant-ca/kaz-sign-128/signing
- prod/tenant-abc123/jwt/kaz-sign-128/access-token
- prod/platform/data/aes-256/encryption
```

### HSM Configuration

```csharp
// appsettings.json
{
  "Hsm": {
    "Provider": "AzureKeyVault",  // AzureKeyVault | Pkcs11 | HashiCorpVault

    "AzureKeyVault": {
      "VaultUri": "https://pqc-identity-vault.vault.azure.net/",
      "ManagedIdentityClientId": null  // Uses DefaultAzureCredential
    },

    "Pkcs11": {
      "LibraryPath": "/usr/lib/softhsm/libsofthsm2.so",
      "TokenLabel": "PQC-IDENTITY-HSM",
      "Pin": ""  // From secret manager
    },

    "HashiCorpVault": {
      "Address": "https://vault.example.com:8200",
      "TransitMountPoint": "transit",
      "AuthMethod": "kubernetes",  // token | kubernetes | approle
      "Role": "pqc-identity-api"
    }
  }
}
```

### HSM Provider Registration

```csharp
// Program.cs or DependencyInjection.cs
public static IServiceCollection AddHsmServices(this IServiceCollection services, IConfiguration configuration)
{
    var hsmConfig = configuration.GetSection("Hsm");
    var provider = hsmConfig.GetValue<string>("Provider");

    services.AddSingleton<IHsmService>(sp => provider switch
    {
        "AzureKeyVault" => new AzureKeyVaultHsmService(
            hsmConfig.GetSection("AzureKeyVault").Get<AzureKeyVaultOptions>()!
        ),
        "Pkcs11" => new Pkcs11HsmService(
            hsmConfig.GetSection("Pkcs11").Get<Pkcs11Options>()!
        ),
        "HashiCorpVault" => new HashiCorpVaultHsmService(
            hsmConfig.GetSection("HashiCorpVault").Get<HashiCorpVaultOptions>()!
        ),
        _ => throw new NotSupportedException($"HSM provider '{provider}' is not supported")
    });

    services.AddScoped<IKeyRotationService, KeyRotationService>();

    // Background service for automatic key rotation
    services.AddHostedService<KeyRotationBackgroundService>();

    return services;
}
```

### Security Considerations for HSM

| Consideration | Recommendation |
|---------------|----------------|
| Access Control | Use RBAC/IAM with least privilege |
| Audit Logging | Enable HSM audit logs, forward to SIEM |
| Key Backup | Use HSM-native backup (never export raw keys) |
| Multi-Region | Replicate HSM configuration for DR |
| Network Security | HSM endpoints in private network only |
| Monitoring | Alert on failed operations, rotation failures |

---

## User Registration Flow

### Overview

The registration flow handles first-time user onboarding, including app installation, identity verification, and cryptographic key generation.

### Registration Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                            USER REGISTRATION FLOW                                │
└─────────────────────────────────────────────────────────────────────────────────┘

  ┌──────────┐          ┌──────────────┐          ┌──────────────┐
  │   User   │          │  Digital ID  │          │   Backend    │
  │          │          │     App      │          │     API      │
  └────┬─────┘          └──────┬───────┘          └──────┬───────┘
       │                       │                         │
       │  1. Download & Install│                         │
       │──────────────────────>│                         │
       │                       │                         │
       │  2. Launch App        │                         │
       │──────────────────────>│                         │
       │                       │                         │
       │  3. Show Onboarding   │                         │
       │<──────────────────────│                         │
       │                       │                         │
       │  4. Enter Org Code    │                         │
       │   or Scan QR Code     │                         │
       │──────────────────────>│                         │
       │                       │                         │
       │                       │  5. Validate Org Code   │
       │                       │────────────────────────>│
       │                       │                         │
       │                       │  6. Return Org Config   │
       │                       │  (PQC algo, branding)   │
       │                       │<────────────────────────│
       │                       │                         │
       │  7. Show Org Welcome  │                         │
       │<──────────────────────│                         │
       │                       │                         │
       │  8. Enter Email       │                         │
       │──────────────────────>│                         │
       │                       │                         │
       │                       │  9. Send Verification   │
       │                       │────────────────────────>│
       │                       │                         │
       │                       │        [Email Sent]     │
       │                       │<────────────────────────│
       │                       │                         │
       │  10. Enter OTP Code   │                         │
       │──────────────────────>│                         │
       │                       │                         │
       │                       │  11. Verify OTP         │
       │                       │────────────────────────>│
       │                       │                         │
       │                       │  12. OTP Valid          │
       │                       │<────────────────────────│
       │                       │                         │
       │  13. Setup Biometrics │                         │
       │<──────────────────────│                         │
       │                       │                         │
       │  14. Authenticate     │                         │
       │   (Face ID/Touch ID)  │                         │
       │──────────────────────>│                         │
       │                       │                         │
       │                       │ [DEVICE-SIDE]           │
       │                       │ 15. Generate PQC        │
       │                       │     Key Pair            │
       │                       │     (ML-DSA or KAZ-SIGN)│
       │                       │                         │
       │                       │ 16. Store Private Key   │
       │                       │     in Secure Enclave   │
       │                       │                         │
       │                       │ 17. Create CSR          │
       │                       │                         │
       │                       │  18. Submit CSR         │
       │                       │────────────────────────>│
       │                       │                         │
       │                       │       [SERVER-SIDE]     │
       │                       │       19. Verify CSR    │
       │                       │       20. Issue Cert    │
       │                       │           (Tenant CA)   │
       │                       │                         │
       │                       │  21. Return Certificate │
       │                       │<────────────────────────│
       │                       │                         │
       │                       │ 22. Store Certificate   │
       │                       │                         │
       │  23. Show Recovery    │                         │
       │      Setup Prompt     │                         │
       │<──────────────────────│                         │
       │                       │                         │
       │  24. Continue to      │                         │
       │      Recovery Setup   │                         │
       │──────────────────────>│                         │
       │                       │                         │
       ▼                       ▼                         ▼
   [Proceed to Recovery Setup Flow]
```

### Registration Steps Detail

#### Step 1-3: App Installation and Launch

```kotlin
// Android - MainActivity.kt
class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val isFirstLaunch = !PreferenceManager.isOnboardingComplete()

        setContent {
            if (isFirstLaunch) {
                OnboardingScreen(
                    onComplete = { navigateToOrgSetup() }
                )
            } else {
                MainAppScreen()
            }
        }
    }
}
```

#### Step 4-7: Organization Discovery

```csharp
// Backend: OrganizationController.cs
[ApiController]
[Route("api/v1/organizations")]
public class OrganizationController : ControllerBase
{
    [HttpGet("discover/{code}")]
    public async Task<ActionResult<OrgDiscoveryResponse>> Discover(string code)
    {
        var org = await _orgService.FindByInviteCodeAsync(code);
        if (org is null)
            return NotFound(new { error = "Invalid organization code" });

        return Ok(new OrgDiscoveryResponse
        {
            OrganizationId = org.Id,
            Name = org.Name,
            LogoUrl = org.LogoUrl,
            PrimaryAlgorithm = org.PrimaryAlgorithm.ToString(),
            RegistrationEndpoint = $"/api/v1/organizations/{org.Slug}/register"
        });
    }
}

public record OrgDiscoveryResponse
{
    public Guid OrganizationId { get; init; }
    public string Name { get; init; } = "";
    public string? LogoUrl { get; init; }
    public string PrimaryAlgorithm { get; init; } = "";  // "ML-DSA-65" or "KAZ-SIGN-128"
    public string RegistrationEndpoint { get; init; } = "";
}
```

#### Step 8-12: Email Verification

```csharp
// Backend: RegistrationService.cs
public class RegistrationService : IRegistrationService
{
    public async Task<Result> InitiateRegistrationAsync(InitiateRegistrationCommand cmd)
    {
        // Check if email already registered
        var existingUser = await _userRepository.FindByEmailAsync(cmd.TenantId, cmd.Email);
        if (existingUser is not null)
            return Result.Failure("Email already registered");

        // Generate 6-digit OTP
        var otp = GenerateSecureOtp();
        var otpHash = HashOtp(otp);

        // Store pending registration
        var pendingReg = new PendingRegistration
        {
            Id = Guid.NewGuid(),
            TenantId = cmd.TenantId,
            Email = cmd.Email,
            OtpHash = otpHash,
            ExpiresAt = DateTime.UtcNow.AddMinutes(10),
            CreatedAt = DateTime.UtcNow
        };

        await _pendingRegistrationRepository.AddAsync(pendingReg);

        // Send email
        await _emailService.SendOtpAsync(cmd.Email, otp, cmd.TenantId);

        return Result.Success(pendingReg.Id);
    }

    public async Task<Result<VerificationToken>> VerifyOtpAsync(Guid pendingId, string otp)
    {
        var pending = await _pendingRegistrationRepository.GetAsync(pendingId);
        if (pending is null || pending.ExpiresAt < DateTime.UtcNow)
            return Result.Failure<VerificationToken>("Invalid or expired registration");

        if (!VerifyOtpHash(otp, pending.OtpHash))
            return Result.Failure<VerificationToken>("Invalid OTP");

        // Generate short-lived verification token for next steps
        var token = new VerificationToken
        {
            Token = GenerateSecureToken(),
            PendingRegistrationId = pendingId,
            ExpiresAt = DateTime.UtcNow.AddMinutes(30)
        };

        await _verificationTokenRepository.AddAsync(token);

        return Result.Success(token);
    }

    private static string GenerateSecureOtp()
    {
        using var rng = RandomNumberGenerator.Create();
        var bytes = new byte[4];
        rng.GetBytes(bytes);
        var number = BitConverter.ToUInt32(bytes, 0) % 1000000;
        return number.ToString("D6");
    }
}
```

#### Step 13-17: Biometrics and Key Generation (Device-Side)

```swift
// iOS/macOS - KeyManager.swift
import LocalAuthentication
import Security
import KazSignNative

final class KeyManager {

    func generateKeyPairWithBiometrics(
        algorithm: PqcAlgorithm,
        userId: String
    ) async throws -> KeyPairResult {

        // Authenticate with biometrics
        let context = LAContext()
        context.localizedReason = "Authenticate to create your digital identity"

        let canEvaluate = try context.canEvaluatePolicy(
            .deviceOwnerAuthenticationWithBiometrics,
            error: nil
        )

        guard canEvaluate else {
            throw KeyManagerError.biometricsNotAvailable
        }

        let authenticated = try await context.evaluatePolicy(
            .deviceOwnerAuthenticationWithBiometrics,
            localizedReason: "Create digital identity keys"
        )

        guard authenticated else {
            throw KeyManagerError.authenticationFailed
        }

        // Generate PQC key pair
        let keyPair: (publicKey: Data, privateKey: Data)

        switch algorithm {
        case .kazSign128, .kazSign192, .kazSign256:
            keyPair = try generateKazSignKeyPair(level: algorithm.kazSignLevel)
        case .mlDsa44, .mlDsa65, .mlDsa87:
            keyPair = try generateMlDsaKeyPair(level: algorithm.mlDsaLevel)
        }

        // Store private key in Keychain with biometric protection
        let privateKeyTag = "com.pqc-identity.\(userId).privateKey"
        try storeInKeychain(
            data: keyPair.privateKey,
            tag: privateKeyTag,
            accessControl: .biometryCurrentSet
        )

        return KeyPairResult(
            publicKey: keyPair.publicKey,
            privateKeyTag: privateKeyTag
        )
    }

    private func generateKazSignKeyPair(level: Int) throws -> (Data, Data) {
        let manager = try KazSignManager(level: SecurityLevel(rawValue: level)!)
        return try manager.generateKeyPair()
    }

    private func storeInKeychain(
        data: Data,
        tag: String,
        accessControl: SecAccessControlCreateFlags
    ) throws {
        let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            accessControl,
            nil
        )!

        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecValueData as String: data,
            kSecAttrAccessControl as String: access
        ]

        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw KeyManagerError.keychainStoreFailed(status)
        }
    }
}
```

#### Step 17-22: CSR Creation and Certificate Issuance

```swift
// iOS - CsrBuilder.swift
struct CsrBuilder {

    func createCsr(
        publicKey: Data,
        privateKeyTag: String,
        subject: CsrSubject,
        algorithm: PqcAlgorithm
    ) throws -> Data {

        // Build CSR structure (simplified)
        var csr = CertificationRequest()
        csr.subject = buildDistinguishedName(subject)
        csr.publicKey = publicKey
        csr.algorithm = algorithm.oid

        // Sign CSR with private key
        let dataToSign = csr.toBeSigned()
        let signature = try signWithKeychain(
            data: dataToSign,
            privateKeyTag: privateKeyTag,
            algorithm: algorithm
        )

        csr.signature = signature

        return csr.toDer()
    }
}
```

```csharp
// Backend: CertificateIssuanceService.cs
public class CertificateIssuanceService : ICertificateIssuanceService
{
    private readonly IHsmService _hsmService;
    private readonly ITenantService _tenantService;

    public async Task<CertificateResult> IssueCertificateAsync(
        IssueCertificateCommand cmd,
        CancellationToken ct)
    {
        // Get tenant CA key from HSM
        var tenant = await _tenantService.GetAsync(cmd.TenantId, ct);
        var caKeyId = tenant.CaKeyId;

        // Parse and validate CSR
        var csr = ParseCsr(cmd.CsrDer);
        if (!ValidateCsrSignature(csr))
            return CertificateResult.Failure("Invalid CSR signature");

        // Build certificate
        var cert = new X509CertificateBuilder()
            .SetSerialNumber(GenerateSerialNumber())
            .SetSubject(csr.Subject)
            .SetPublicKey(csr.PublicKey)
            .SetNotBefore(DateTime.UtcNow)
            .SetNotAfter(DateTime.UtcNow.AddDays(tenant.Settings.CertificateValidityDays))
            .SetIssuer(tenant.CaSubject)
            .AddExtension(BasicConstraints.EndEntity())
            .AddExtension(KeyUsage.DigitalSignature | KeyUsage.NonRepudiation)
            .AddExtension(ExtendedKeyUsage.ClientAuth)
            .Build();

        // Sign with tenant CA key via HSM
        var signature = await _hsmService.SignAsync(
            caKeyId,
            cert.ToBeSigned,
            tenant.PrimaryAlgorithm.ToSignatureAlgorithm(),
            ct
        );

        cert.AttachSignature(signature);

        // Store certificate metadata
        var certRecord = new UserCertificate
        {
            Id = Guid.NewGuid(),
            UserId = cmd.UserId,
            TenantId = cmd.TenantId,
            SerialNumber = cert.SerialNumber,
            Thumbprint = cert.Thumbprint,
            IssuedAt = DateTime.UtcNow,
            ExpiresAt = cert.NotAfter,
            Status = CertificateStatus.Active
        };

        await _certificateRepository.AddAsync(certRecord, ct);

        return CertificateResult.Success(cert.ToDer());
    }
}
```

### Registration Data Model

```csharp
public class PendingRegistration
{
    public Guid Id { get; set; }
    public Guid TenantId { get; set; }
    public string Email { get; set; } = "";
    public string OtpHash { get; set; } = "";
    public DateTime ExpiresAt { get; set; }
    public DateTime CreatedAt { get; set; }
    public int AttemptCount { get; set; }
}

public class User
{
    public Guid Id { get; set; }
    public Guid TenantId { get; set; }
    public string Email { get; set; } = "";
    public string? DisplayName { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime? LastAuthAt { get; set; }
    public UserStatus Status { get; set; }

    // Navigation
    public ICollection<UserDevice> Devices { get; set; } = new List<UserDevice>();
    public ICollection<UserCertificate> Certificates { get; set; } = new List<UserCertificate>();
    public ICollection<RecoveryMethod> RecoveryMethods { get; set; } = new List<RecoveryMethod>();
}

public class UserDevice
{
    public Guid Id { get; set; }
    public Guid UserId { get; set; }
    public string DeviceId { get; set; } = "";  // Unique device identifier
    public string DeviceName { get; set; } = ""; // "iPhone 15 Pro", "Galaxy S24"
    public DevicePlatform Platform { get; set; }
    public string? PushToken { get; set; }
    public DateTime RegisteredAt { get; set; }
    public DateTime LastSeenAt { get; set; }
    public bool IsPrimary { get; set; }
}

public enum DevicePlatform
{
    iOS,
    Android,
    macOS,
    Windows
}

public enum UserStatus
{
    Active,
    Suspended,
    PendingRecovery,
    Deactivated
}
```

---

## Account Recovery Flow

### Overview

The recovery flow is critical for users who lose access to their device (lost phone, accidental app deletion, device upgrade). It must balance security with usability.

### Recovery Methods

| Method | Security Level | User Experience | Recommended For |
|--------|---------------|-----------------|-----------------|
| Recovery Code | High | Medium | All users (mandatory) |
| Trusted Device | High | Easy | Multi-device users |
| Admin Recovery | Medium | Slow | Enterprise managed |
| Social Recovery | Medium | Complex | Advanced users |

### Recovery Setup Flow (During Registration)

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                         RECOVERY SETUP FLOW                                      │
└─────────────────────────────────────────────────────────────────────────────────┘

  ┌──────────┐          ┌──────────────┐          ┌──────────────┐
  │   User   │          │  Digital ID  │          │   Backend    │
  │          │          │     App      │          │     API      │
  └────┬─────┘          └──────┬───────┘          └──────┬───────┘
       │                       │                         │
       │                       │  1. Generate Recovery   │
       │                       │     Code (24 words)     │
       │                       │                         │
       │  2. Display Recovery  │                         │
       │     Code Words        │                         │
       │<──────────────────────│                         │
       │                       │                         │
       │  3. User writes down  │                         │
       │     recovery words    │                         │
       │                       │                         │
       │  4. Tap "I've saved   │                         │
       │     my recovery code" │                         │
       │──────────────────────>│                         │
       │                       │                         │
       │  5. Verification:     │                         │
       │     Enter words       │                         │
       │     3, 7, 15, 22      │                         │
       │<──────────────────────│                         │
       │                       │                         │
       │  6. Enter selected    │                         │
       │     words             │                         │
       │──────────────────────>│                         │
       │                       │                         │
       │                       │  7. Verify words match  │
       │                       │                         │
       │                       │ [DEVICE-SIDE]           │
       │                       │ 8. Hash recovery code   │
       │                       │    with HKDF            │
       │                       │                         │
       │                       │ 9. Encrypt private key  │
       │                       │    with derived key     │
       │                       │                         │
       │                       │  10. Store encrypted    │
       │                       │      key backup         │
       │                       │─────────────────────────>
       │                       │                         │
       │                       │  11. Store recovery     │
       │                       │      code hash          │
       │                       │      (for verification) │
       │                       │                         │
       │                       │  12. Backup stored      │
       │                       │<─────────────────────────
       │                       │                         │
       │  13. Recovery Setup   │                         │
       │      Complete!        │                         │
       │<──────────────────────│                         │
       │                       │                         │
       │  14. Optional:        │                         │
       │      Add Trusted      │                         │
       │      Device           │                         │
       │<──────────────────────│                         │
       │                       │                         │
       ▼                       ▼                         ▼
```

### Recovery Code Generation (BIP-39 Style)

```swift
// iOS - RecoveryCodeGenerator.swift
import CryptoKit

final class RecoveryCodeGenerator {

    // BIP-39 word list (2048 words)
    private static let wordList: [String] = loadBip39WordList()

    /// Generate 24-word recovery phrase (256-bit entropy)
    func generateRecoveryCode() -> RecoveryCode {
        // Generate 256 bits of entropy
        var entropy = [UInt8](repeating: 0, count: 32)
        let status = SecRandomCopyBytes(kSecRandomDefault, entropy.count, &entropy)
        guard status == errSecSuccess else {
            fatalError("Failed to generate random bytes")
        }

        // Calculate checksum (first byte of SHA-256)
        let hash = SHA256.hash(data: Data(entropy))
        let checksum = hash.first!

        // Combine entropy + checksum (264 bits = 24 words × 11 bits)
        var bits = entropy.map { byteToBits($0) }.joined()
        bits += byteToBits(checksum).prefix(8)

        // Convert to word indices (11 bits each)
        let words = stride(from: 0, to: 264, by: 11).map { i -> String in
            let indexBits = String(bits.dropFirst(i).prefix(11))
            let index = Int(indexBits, radix: 2)!
            return Self.wordList[index]
        }

        return RecoveryCode(words: words, entropy: Data(entropy))
    }

    /// Derive encryption key from recovery code
    func deriveKeyFromRecoveryCode(_ words: [String]) throws -> SymmetricKey {
        // Reconstruct entropy from words
        let entropy = try reconstructEntropy(from: words)

        // Use HKDF to derive encryption key
        let info = "PQC-Identity-Recovery-v1".data(using: .utf8)!
        let salt = "pqc-identity-salt".data(using: .utf8)!

        let derivedKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: entropy),
            salt: salt,
            info: info,
            outputByteCount: 32
        )

        return derivedKey
    }

    /// Encrypt private key with recovery-derived key
    func encryptPrivateKey(
        privateKey: Data,
        recoveryCode: RecoveryCode
    ) throws -> EncryptedKeyBackup {

        let encryptionKey = try deriveKeyFromRecoveryCode(recoveryCode.words)

        // Use AES-GCM for encryption
        let nonce = AES.GCM.Nonce()
        let sealed = try AES.GCM.seal(privateKey, using: encryptionKey, nonce: nonce)

        return EncryptedKeyBackup(
            ciphertext: sealed.ciphertext,
            nonce: Data(nonce),
            tag: sealed.tag
        )
    }
}

struct RecoveryCode {
    let words: [String]
    let entropy: Data

    var displayWords: String {
        words.enumerated().map { "\($0.offset + 1). \($0.element)" }.joined(separator: "\n")
    }
}

struct EncryptedKeyBackup: Codable {
    let ciphertext: Data
    let nonce: Data
    let tag: Data
}
```

### Recovery Execution Flow (When User Loses Access)

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                         ACCOUNT RECOVERY FLOW                                    │
└─────────────────────────────────────────────────────────────────────────────────┘

  ┌──────────┐          ┌──────────────┐          ┌──────────────┐
  │   User   │          │  New Device  │          │   Backend    │
  │          │          │  Digital ID  │          │     API      │
  └────┬─────┘          └──────┬───────┘          └──────┬───────┘
       │                       │                         │
       │  1. Install app on    │                         │
       │     new device        │                         │
       │──────────────────────>│                         │
       │                       │                         │
       │  2. Tap "Recover      │                         │
       │     Existing Account" │                         │
       │──────────────────────>│                         │
       │                       │                         │
       │  3. Enter Org Code    │                         │
       │──────────────────────>│                         │
       │                       │                         │
       │                       │  4. Get Org Config      │
       │                       │────────────────────────>│
       │                       │                         │
       │                       │<────────────────────────│
       │                       │                         │
       │  5. Enter Email       │                         │
       │──────────────────────>│                         │
       │                       │                         │
       │                       │  6. Initiate Recovery   │
       │                       │────────────────────────>│
       │                       │                         │
       │                       │  7. Send Recovery Email │
       │                       │     (if email matches)  │
       │                       │<────────────────────────│
       │                       │                         │
       │  8. Click link in     │                         │
       │     email OR enter OTP│                         │
       │──────────────────────>│                         │
       │                       │                         │
       │                       │  9. Verify Recovery     │
       │                       │────────────────────────>│
       │                       │                         │
       │                       │  10. Return encrypted   │
       │                       │      key backup         │
       │                       │<────────────────────────│
       │                       │                         │
       │  11. Enter 24-word    │                         │
       │      recovery code    │                         │
       │──────────────────────>│                         │
       │                       │                         │
       │                       │ [DEVICE-SIDE]           │
       │                       │ 12. Derive key from     │
       │                       │     recovery code       │
       │                       │                         │
       │                       │ 13. Decrypt private key │
       │                       │                         │
       │                       │ 14. Store in Secure     │
       │                       │     Enclave             │
       │                       │                         │
       │  15. Setup Biometrics │                         │
       │<──────────────────────│                         │
       │                       │                         │
       │  16. Authenticate     │                         │
       │──────────────────────>│                         │
       │                       │                         │
       │                       │  17. Register new       │
       │                       │      device             │
       │                       │────────────────────────>│
       │                       │                         │
       │                       │  18. Revoke old device  │
       │                       │      (optional)         │
       │                       │                         │
       │                       │<────────────────────────│
       │                       │                         │
       │  19. Recovery         │                         │
       │      Complete!        │                         │
       │<──────────────────────│                         │
       │                       │                         │
       ▼                       ▼                         ▼
```

### Backend Recovery Service

```csharp
// Backend: RecoveryService.cs
public class RecoveryService : IRecoveryService
{
    public async Task<Result> InitiateRecoveryAsync(InitiateRecoveryCommand cmd, CancellationToken ct)
    {
        // Find user by email
        var user = await _userRepository.FindByEmailAsync(cmd.TenantId, cmd.Email, ct);
        if (user is null)
        {
            // Don't reveal if user exists - use generic message
            _logger.LogInformation("Recovery initiated for unknown email: {Email}", cmd.Email);
            return Result.Success(); // Pretend success
        }

        // Check if user has recovery methods configured
        var recoveryMethods = await _recoveryMethodRepository.GetByUserAsync(user.Id, ct);
        if (!recoveryMethods.Any())
        {
            _logger.LogWarning("User {UserId} has no recovery methods", user.Id);
            return Result.Success(); // Pretend success
        }

        // Create recovery session
        var session = new RecoverySession
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            TenantId = cmd.TenantId,
            NewDeviceId = cmd.DeviceId,
            Status = RecoveryStatus.PendingVerification,
            CreatedAt = DateTime.UtcNow,
            ExpiresAt = DateTime.UtcNow.AddHours(1)
        };

        await _recoverySessionRepository.AddAsync(session, ct);

        // Send recovery email
        var otp = GenerateSecureOtp();
        await _emailService.SendRecoveryOtpAsync(user.Email, otp, session.Id, ct);

        // Store hashed OTP
        session.OtpHash = HashOtp(otp);
        await _recoverySessionRepository.UpdateAsync(session, ct);

        return Result.Success(session.Id);
    }

    public async Task<Result<EncryptedKeyBackup>> VerifyAndGetBackupAsync(
        VerifyRecoveryCommand cmd,
        CancellationToken ct)
    {
        var session = await _recoverySessionRepository.GetAsync(cmd.SessionId, ct);
        if (session is null || session.ExpiresAt < DateTime.UtcNow)
            return Result.Failure<EncryptedKeyBackup>("Invalid or expired session");

        if (!VerifyOtpHash(cmd.Otp, session.OtpHash))
            return Result.Failure<EncryptedKeyBackup>("Invalid verification code");

        // Get the user's encrypted key backup
        var recovery = await _recoveryMethodRepository.GetCodeRecoveryAsync(session.UserId, ct);
        if (recovery is null)
            return Result.Failure<EncryptedKeyBackup>("No recovery backup found");

        // Mark session as verified
        session.Status = RecoveryStatus.Verified;
        session.VerifiedAt = DateTime.UtcNow;
        await _recoverySessionRepository.UpdateAsync(session, ct);

        // Audit log
        await _auditService.LogAsync(new AuditEntry
        {
            UserId = session.UserId,
            TenantId = session.TenantId,
            Action = "RecoveryInitiated",
            Details = new { DeviceId = cmd.DeviceId, SessionId = session.Id }
        }, ct);

        return Result.Success(new EncryptedKeyBackup
        {
            Ciphertext = recovery.EncryptedPrivateKey,
            Nonce = recovery.Nonce,
            Tag = recovery.AuthTag
        });
    }

    public async Task<Result> CompleteRecoveryAsync(CompleteRecoveryCommand cmd, CancellationToken ct)
    {
        var session = await _recoverySessionRepository.GetAsync(cmd.SessionId, ct);
        if (session?.Status != RecoveryStatus.Verified)
            return Result.Failure("Invalid recovery session");

        // Register new device
        var device = new UserDevice
        {
            Id = Guid.NewGuid(),
            UserId = session.UserId,
            DeviceId = cmd.DeviceId,
            DeviceName = cmd.DeviceName,
            Platform = cmd.Platform,
            RegisteredAt = DateTime.UtcNow,
            LastSeenAt = DateTime.UtcNow,
            IsPrimary = true
        };

        await _deviceRepository.AddAsync(device, ct);

        // Optionally revoke old devices
        if (cmd.RevokeOldDevices)
        {
            var oldDevices = await _deviceRepository.GetByUserAsync(session.UserId, ct);
            foreach (var oldDevice in oldDevices.Where(d => d.Id != device.Id))
            {
                oldDevice.RevokedAt = DateTime.UtcNow;
                oldDevice.RevokedReason = "Account recovery";
            }
            await _deviceRepository.UpdateRangeAsync(oldDevices, ct);
        }

        // Mark recovery complete
        session.Status = RecoveryStatus.Completed;
        session.CompletedAt = DateTime.UtcNow;
        await _recoverySessionRepository.UpdateAsync(session, ct);

        // Audit log
        await _auditService.LogAsync(new AuditEntry
        {
            UserId = session.UserId,
            TenantId = session.TenantId,
            Action = "RecoveryCompleted",
            Details = new {
                NewDeviceId = device.Id,
                RevokedOldDevices = cmd.RevokeOldDevices
            }
        }, ct);

        return Result.Success();
    }
}
```

### Recovery Data Model

```csharp
public class RecoveryMethod
{
    public Guid Id { get; set; }
    public Guid UserId { get; set; }
    public RecoveryMethodType Type { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime? LastUsedAt { get; set; }
    public bool IsActive { get; set; }
}

public class CodeRecoveryMethod : RecoveryMethod
{
    // Recovery code hash (for verification only - actual decryption happens client-side)
    public string RecoveryCodeHash { get; set; } = "";

    // Encrypted private key (encrypted with recovery-derived key)
    public byte[] EncryptedPrivateKey { get; set; } = [];
    public byte[] Nonce { get; set; } = [];
    public byte[] AuthTag { get; set; } = [];

    // Algorithm used for the key
    public PqcAlgorithm Algorithm { get; set; }
}

public class TrustedDeviceRecoveryMethod : RecoveryMethod
{
    public Guid TrustedDeviceId { get; set; }
    public string DeviceName { get; set; } = "";
}

public class RecoverySession
{
    public Guid Id { get; set; }
    public Guid UserId { get; set; }
    public Guid TenantId { get; set; }
    public string? NewDeviceId { get; set; }
    public RecoveryStatus Status { get; set; }
    public string? OtpHash { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime ExpiresAt { get; set; }
    public DateTime? VerifiedAt { get; set; }
    public DateTime? CompletedAt { get; set; }
}

public enum RecoveryMethodType
{
    RecoveryCode,
    TrustedDevice,
    AdminRecovery,
    SocialRecovery
}

public enum RecoveryStatus
{
    PendingVerification,
    Verified,
    Completed,
    Expired,
    Cancelled
}
```

### Security Considerations for Recovery

| Consideration | Implementation |
|---------------|----------------|
| Recovery code storage | User stores offline (paper, password manager) |
| Rate limiting | Max 3 recovery attempts per hour |
| Device revocation | Option to revoke old devices on recovery |
| Audit trail | Log all recovery attempts and completions |
| Email verification | Required before providing encrypted backup |
| Time limits | Recovery session expires in 1 hour |
| Recovery code hash | Only store hash, not the actual code |
| Encrypted backup | Private key encrypted with recovery-derived key |

### Alternative: Trusted Device Recovery

For users with multiple devices, trusted device recovery provides a seamless experience:

```
┌───────────┐         ┌───────────┐         ┌──────────┐
│ Old Device│         │New Device │         │ Backend  │
└─────┬─────┘         └─────┬─────┘         └────┬─────┘
      │                     │                     │
      │                     │ 1. Request recovery │
      │                     │────────────────────>│
      │                     │                     │
      │  2. Push notification: "Approve new device?"
      │<──────────────────────────────────────────│
      │                     │                     │
      │ 3. User approves    │                     │
      │    with biometrics  │                     │
      │─────────────────────────────────────────> │
      │                     │                     │
      │                     │ 4. Transfer encrypted
      │                     │    key material     │
      │                     │<────────────────────│
      │                     │                     │
      │                     │ 5. Decrypt and      │
      │                     │    store locally    │
      │                     │                     │
      ▼                     ▼                     ▼
```

---

## Future Considerations

### Potential Enhancements

1. **Hybrid Certificates** - Classical + PQC signatures for transition period
2. **Hardware Security Module (HSM)** - Integration for enterprise deployments
3. **Decentralized Identity** - DID/Verifiable Credentials support
4. **Additional PQC Algorithms** - Falcon, SPHINCS+ when needed

### Migration Path to Microservices

If scaling requires, modules can be extracted:

1. Identity Module → Identity Service
2. Certificate Module → CA Service
3. Admin Module → Admin Service

Each service would communicate via:
- REST APIs for synchronous calls
- Message queue for async events

---

## References

- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [.NET 10 PQC Support](https://devblogs.microsoft.com/dotnet/post-quantum-cryptography-in-dotnet/)
- [OIDC Specification](https://openid.net/specs/openid-connect-core-1_0.html)
- [FIDO2/WebAuthn](https://fidoalliance.org/fido2/)
- [KAZ-SIGN Documentation](./libs/kazsign/README.md)
