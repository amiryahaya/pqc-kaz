using FluentAssertions;
using PqcIdentity.Identity.Domain.Entities;

namespace PqcIdentity.Tests.Unit.Identity;

/// <summary>
/// Unit tests for RecoveryToken entity.
/// </summary>
public class RecoveryTokenTests
{
    [Fact]
    public void Create_WithValidData_ShouldCreateRecoveryToken()
    {
        // Arrange
        var userId = Guid.CreateVersion7();
        var tokenHash = "abc123hash";
        var keyShareId = Guid.CreateVersion7();

        // Act
        var token = RecoveryToken.Create(userId, tokenHash, keyShareId);

        // Assert
        token.Should().NotBeNull();
        token.Id.Should().NotBeEmpty();
        token.UserId.Should().Be(userId);
        token.TokenHash.Should().Be(tokenHash);
        token.KeyShareId.Should().Be(keyShareId);
        token.IsActive.Should().BeTrue();
        token.UseCount.Should().Be(0);
        token.TokenVersion.Should().Be(1);
    }

    [Fact]
    public void Create_WithTokenVersion_ShouldSetVersion()
    {
        // Arrange
        var userId = Guid.CreateVersion7();
        var tokenHash = "abc123hash";
        var keyShareId = Guid.CreateVersion7();
        var version = 3;

        // Act
        var token = RecoveryToken.Create(userId, tokenHash, keyShareId, tokenVersion: version);

        // Assert
        token.TokenVersion.Should().Be(version);
    }

    [Fact]
    public void RecordUsage_ShouldIncrementUseCountAndSetLastUsed()
    {
        // Arrange
        var token = CreateValidToken();
        var ipAddress = "192.168.1.1";
        var beforeUsage = DateTimeOffset.UtcNow;

        // Act
        token.RecordUsage(ipAddress);

        // Assert
        token.UseCount.Should().Be(1);
        token.LastUsedAt.Should().NotBeNull();
        token.LastUsedAt.Should().BeOnOrAfter(beforeUsage);
        token.LastRecoveryIp.Should().Be(ipAddress);
    }

    [Fact]
    public void RecordUsage_CalledMultipleTimes_ShouldIncrementCount()
    {
        // Arrange
        var token = CreateValidToken();

        // Act
        token.RecordUsage("ip1");
        token.RecordUsage("ip2");
        token.RecordUsage("ip3");

        // Assert
        token.UseCount.Should().Be(3);
        token.LastRecoveryIp.Should().Be("ip3");
    }

    [Fact]
    public void Deactivate_ShouldSetIsActiveToFalse()
    {
        // Arrange
        var token = CreateValidToken();
        token.IsActive.Should().BeTrue();

        // Act
        token.Deactivate();

        // Assert
        token.IsActive.Should().BeFalse();
    }

    [Fact]
    public void VerifyTokenHash_WithMatchingHash_ShouldReturnTrue()
    {
        // Arrange
        var tokenHash = "correcthash";
        var token = RecoveryToken.Create(
            Guid.CreateVersion7(),
            tokenHash,
            Guid.CreateVersion7());

        // Act & Assert
        token.VerifyTokenHash(tokenHash).Should().BeTrue();
    }

    [Fact]
    public void VerifyTokenHash_WithNonMatchingHash_ShouldReturnFalse()
    {
        // Arrange
        var token = RecoveryToken.Create(
            Guid.CreateVersion7(),
            "correcthash",
            Guid.CreateVersion7());

        // Act & Assert
        token.VerifyTokenHash("wronghash").Should().BeFalse();
    }

    [Fact]
    public void VerifyTokenHash_ShouldBeCaseInsensitive()
    {
        // Arrange
        var token = RecoveryToken.Create(
            Guid.CreateVersion7(),
            "AbCdEf123",
            Guid.CreateVersion7());

        // Act & Assert
        token.VerifyTokenHash("ABCDEF123").Should().BeTrue();
        token.VerifyTokenHash("abcdef123").Should().BeTrue();
    }

    private static RecoveryToken CreateValidToken()
    {
        return RecoveryToken.Create(
            userId: Guid.CreateVersion7(),
            tokenHash: "testhash123",
            keyShareId: Guid.CreateVersion7());
    }
}
