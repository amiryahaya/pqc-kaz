using Testcontainers.PostgreSql;

namespace PqcIdentity.Tests.Integration.Fixtures;

/// <summary>
/// Fixture for managing PostgreSQL test container.
/// </summary>
public class PostgresContainerFixture : IAsyncLifetime
{
    private PostgreSqlContainer? _container;

    public string ConnectionString => _container?.GetConnectionString()
        ?? throw new InvalidOperationException("Container not initialized");

    public async Task InitializeAsync()
    {
        _container = new PostgreSqlBuilder()
            .WithImage("postgres:16-alpine")
            .WithDatabase("pqc_identity_test")
            .WithUsername("test_user")
            .WithPassword("test_password")
            .WithCleanUp(true)
            .Build();

        await _container.StartAsync();
    }

    public async Task DisposeAsync()
    {
        if (_container is not null)
        {
            await _container.DisposeAsync();
        }
    }
}

/// <summary>
/// Collection definition for PostgreSQL container tests.
/// </summary>
[CollectionDefinition("PostgreSQL")]
public class PostgresCollection : ICollectionFixture<PostgresContainerFixture>
{
}
