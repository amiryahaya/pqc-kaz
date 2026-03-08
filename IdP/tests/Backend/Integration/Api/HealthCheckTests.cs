using System.Net;
using FluentAssertions;
using PqcIdentity.Tests.Integration.Fixtures;

namespace PqcIdentity.Tests.Integration.Api;

/// <summary>
/// Integration tests for health check endpoints.
/// </summary>
public class HealthCheckTests : IClassFixture<CustomWebApplicationFactory>
{
    private readonly HttpClient _client;

    public HealthCheckTests(CustomWebApplicationFactory factory)
    {
        _client = factory.CreateClient();
    }

    [Fact]
    public async Task HealthCheck_ShouldReturnOk()
    {
        // Act
        var response = await _client.GetAsync("/health");

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task LivenessCheck_ShouldReturnOk()
    {
        // Act
        var response = await _client.GetAsync("/health/live");

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task ReadinessCheck_ShouldReturnStatus()
    {
        // Act
        var response = await _client.GetAsync("/health/ready");

        // Assert
        // May return OK or ServiceUnavailable depending on database
        response.StatusCode.Should().BeOneOf(HttpStatusCode.OK, HttpStatusCode.ServiceUnavailable);
    }
}
