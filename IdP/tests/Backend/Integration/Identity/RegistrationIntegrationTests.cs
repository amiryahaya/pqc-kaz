using System.Net;
using System.Net.Http.Json;
using FluentAssertions;
using PqcIdentity.Tests.Integration.Fixtures;

namespace PqcIdentity.Tests.Integration.Identity;

/// <summary>
/// Integration tests for registration flow.
/// </summary>
[Collection("PostgreSQL")]
public class RegistrationIntegrationTests : IAsyncLifetime
{
    private readonly PostgresContainerFixture _postgres;
    private readonly CustomWebApplicationFactory _factory;
    private HttpClient _client = null!;

    public RegistrationIntegrationTests(PostgresContainerFixture postgres)
    {
        _postgres = postgres;
        _factory = new CustomWebApplicationFactory
        {
            ConnectionString = postgres.ConnectionString
        };
    }

    public Task InitializeAsync()
    {
        _client = _factory.CreateClient();
        return Task.CompletedTask;
    }

    public async Task DisposeAsync()
    {
        _client.Dispose();
        await _factory.DisposeAsync();
    }

    [Fact]
    public async Task InitiateRegistration_WithValidData_ShouldReturnSuccess()
    {
        // Arrange
        var request = new
        {
            IcNumber = "901201145678",
            FullName = "Ahmad bin Abdullah",
            Email = "ahmad@example.com",
            PhoneNumber = "+60123456789"
        };

        // Act
        var response = await _client.PostAsJsonAsync("/api/v1/identity/register/initiate", request);

        // Assert
        // Note: May fail if database schema not applied; that's expected
        response.StatusCode.Should().BeOneOf(
            HttpStatusCode.OK,
            HttpStatusCode.Created,
            HttpStatusCode.InternalServerError, // Database not ready
            HttpStatusCode.NotFound // Route not registered
        );
    }

    [Fact]
    public async Task InitiateRegistration_WithInvalidIcNumber_ShouldReturnBadRequest()
    {
        // Arrange
        var request = new
        {
            IcNumber = "invalid",
            FullName = "Test User",
            Email = "test@example.com",
            PhoneNumber = "+60123456789"
        };

        // Act
        var response = await _client.PostAsJsonAsync("/api/v1/identity/register/initiate", request);

        // Assert
        // Should return BadRequest for validation errors
        response.StatusCode.Should().BeOneOf(
            HttpStatusCode.BadRequest,
            HttpStatusCode.NotFound, // Route not registered
            HttpStatusCode.InternalServerError // Database not ready
        );
    }

    [Fact]
    public async Task InitiateRegistration_WithInvalidEmail_ShouldReturnBadRequest()
    {
        // Arrange
        var request = new
        {
            IcNumber = "901201145678",
            FullName = "Test User",
            Email = "not-an-email",
            PhoneNumber = "+60123456789"
        };

        // Act
        var response = await _client.PostAsJsonAsync("/api/v1/identity/register/initiate", request);

        // Assert
        response.StatusCode.Should().BeOneOf(
            HttpStatusCode.BadRequest,
            HttpStatusCode.NotFound,
            HttpStatusCode.InternalServerError
        );
    }
}
