using FluentAssertions;
using PqcIdentity.Crypto.Domain.Entities;
using PqcIdentity.Crypto.Domain.Enums;
using PqcIdentity.Crypto.Domain.Events;

namespace PqcIdentity.Tests.Unit.Crypto;

/// <summary>
/// Unit tests for CryptoKey entity.
/// </summary>
public class CryptoKeyTests
{
    [Fact]
    public void CreateSoftwareKey_WithValidData_ShouldCreateKey()
    {
        // Arrange
        var label = "Test Key";
        var publicKey = new byte[2592]; // KAZ-SIGN-256 public key size
        var encryptedPrivateKey = new byte[5000];
        var fingerprint = "abc123def456";
        var expiresAt = DateTimeOffset.UtcNow.AddYears(1);
        var userId = Guid.CreateVersion7();

        // Act
        var key = CryptoKey.CreateSoftwareKey(
            label: label,
            algorithm: KeyAlgorithm.KazSign256,
            purpose: KeyPurpose.Signing,
            publicKey: publicKey,
            encryptedPrivateKey: encryptedPrivateKey,
            keyFingerprint: fingerprint,
            expiresAt: expiresAt,
            userId: userId);

        // Assert
        key.Should().NotBeNull();
        key.Id.Should().NotBeEmpty();
        key.Label.Should().Be(label);
        key.Algorithm.Should().Be(KeyAlgorithm.KazSign256);
        key.Purpose.Should().Be(KeyPurpose.Signing);
        key.Status.Should().Be(KeyStatus.Active);
        key.StorageType.Should().Be(KeyStorageType.Software);
        key.PublicKey.Should().BeEquivalentTo(publicKey);
        key.EncryptedPrivateKey.Should().BeEquivalentTo(encryptedPrivateKey);
        key.KeyFingerprint.Should().Be(fingerprint);
        key.ExpiresAt.Should().Be(expiresAt);
        key.UserId.Should().Be(userId);
        key.UseCount.Should().Be(0);
    }

    [Fact]
    public void CreateHsmKey_WithValidData_ShouldCreateKey()
    {
        // Arrange
        var label = "HSM Key";
        var publicKey = new byte[2592];
        var hsmHandle = "hsm://slot/123/key/456";
        var fingerprint = "xyz789";

        // Act
        var key = CryptoKey.CreateHsmKey(
            label: label,
            algorithm: KeyAlgorithm.KazSign256,
            purpose: KeyPurpose.Signing,
            publicKey: publicKey,
            hsmKeyHandle: hsmHandle,
            keyFingerprint: fingerprint);

        // Assert
        key.Should().NotBeNull();
        key.StorageType.Should().Be(KeyStorageType.Hsm);
        key.HsmKeyHandle.Should().Be(hsmHandle);
        key.EncryptedPrivateKey.Should().BeNull();
    }

    [Fact]
    public void CreateSoftwareKey_ShouldRaiseKeyGeneratedEvent()
    {
        // Arrange & Act
        var key = CreateValidSoftwareKey();

        // Assert
        key.DomainEvents.Should().ContainSingle();
        key.DomainEvents.First().Should().BeOfType<KeyGeneratedEvent>();
    }

    [Fact]
    public void IsUsable_WhenActiveAndNotExpired_ShouldReturnTrue()
    {
        // Arrange
        var key = CreateValidSoftwareKey();

        // Act & Assert
        key.IsUsable().Should().BeTrue();
    }

    [Fact]
    public void IsUsable_WhenDisabled_ShouldReturnFalse()
    {
        // Arrange
        var key = CreateValidSoftwareKey();
        key.Disable();

        // Act & Assert
        key.IsUsable().Should().BeFalse();
    }

    [Fact]
    public void IsUsable_WhenExpired_ShouldReturnFalse()
    {
        // Arrange
        var key = CryptoKey.CreateSoftwareKey(
            label: "Expired Key",
            algorithm: KeyAlgorithm.KazSign256,
            purpose: KeyPurpose.Signing,
            publicKey: new byte[2592],
            encryptedPrivateKey: new byte[5000],
            keyFingerprint: "fingerprint",
            expiresAt: DateTimeOffset.UtcNow.AddDays(-1));

        // Act & Assert
        key.IsUsable().Should().BeFalse();
    }

    [Fact]
    public void RecordUsage_ShouldIncrementUseCountAndUpdateLastUsed()
    {
        // Arrange
        var key = CreateValidSoftwareKey();
        var beforeUsage = DateTimeOffset.UtcNow;

        // Act
        key.RecordUsage();

        // Assert
        key.UseCount.Should().Be(1);
        key.LastUsedAt.Should().NotBeNull();
        key.LastUsedAt.Should().BeOnOrAfter(beforeUsage);
    }

    [Fact]
    public void RecordUsage_CalledMultipleTimes_ShouldIncrementCount()
    {
        // Arrange
        var key = CreateValidSoftwareKey();

        // Act
        key.RecordUsage();
        key.RecordUsage();
        key.RecordUsage();

        // Assert
        key.UseCount.Should().Be(3);
    }

    [Fact]
    public void Disable_WhenActive_ShouldSetStatusToDisabled()
    {
        // Arrange
        var key = CreateValidSoftwareKey();
        key.ClearDomainEvents();

        // Act
        key.Disable();

        // Assert
        key.Status.Should().Be(KeyStatus.Disabled);
        key.DomainEvents.Should().ContainSingle();
        key.DomainEvents.First().Should().BeOfType<KeyDisabledEvent>();
    }

    [Fact]
    public void Disable_WhenDestroyed_ShouldThrow()
    {
        // Arrange
        var key = CreateValidSoftwareKey();
        key.Destroy();

        // Act & Assert
        var act = () => key.Disable();
        act.Should().Throw<InvalidOperationException>();
    }

    [Fact]
    public void Enable_WhenDisabled_ShouldSetStatusToActive()
    {
        // Arrange
        var key = CreateValidSoftwareKey();
        key.Disable();
        key.ClearDomainEvents();

        // Act
        key.Enable();

        // Assert
        key.Status.Should().Be(KeyStatus.Active);
        key.DomainEvents.Should().ContainSingle();
        key.DomainEvents.First().Should().BeOfType<KeyEnabledEvent>();
    }

    [Fact]
    public void Enable_WhenNotDisabled_ShouldThrow()
    {
        // Arrange
        var key = CreateValidSoftwareKey();

        // Act & Assert
        var act = () => key.Enable();
        act.Should().Throw<InvalidOperationException>();
    }

    [Fact]
    public void MarkCompromised_ShouldSetStatusToCompromised()
    {
        // Arrange
        var key = CreateValidSoftwareKey();
        key.ClearDomainEvents();

        // Act
        key.MarkCompromised();

        // Assert
        key.Status.Should().Be(KeyStatus.Compromised);
        key.DomainEvents.Should().ContainSingle();
        key.DomainEvents.First().Should().BeOfType<KeyCompromisedEvent>();
    }

    [Fact]
    public void MarkCompromised_WhenDestroyed_ShouldNotChange()
    {
        // Arrange
        var key = CreateValidSoftwareKey();
        key.Destroy();

        // Act
        key.MarkCompromised();

        // Assert
        key.Status.Should().Be(KeyStatus.Destroyed);
    }

    [Fact]
    public void Destroy_ShouldSetStatusAndClearPrivateKey()
    {
        // Arrange
        var key = CreateValidSoftwareKey();
        key.ClearDomainEvents();

        // Act
        key.Destroy();

        // Assert
        key.Status.Should().Be(KeyStatus.Destroyed);
        key.EncryptedPrivateKey.Should().BeNull();
        key.DomainEvents.Should().ContainSingle();
        key.DomainEvents.First().Should().BeOfType<KeyDestroyedEvent>();
    }

    [Fact]
    public void Destroy_WhenAlreadyDestroyed_ShouldNotRaiseEvent()
    {
        // Arrange
        var key = CreateValidSoftwareKey();
        key.Destroy();
        key.ClearDomainEvents();

        // Act
        key.Destroy();

        // Assert
        key.DomainEvents.Should().BeEmpty();
    }

    [Fact]
    public void UpdateLabel_ShouldChangeLabel()
    {
        // Arrange
        var key = CreateValidSoftwareKey();
        var newLabel = "Updated Label";

        // Act
        key.UpdateLabel(newLabel);

        // Assert
        key.Label.Should().Be(newLabel);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(null)]
    public void UpdateLabel_WithInvalidLabel_ShouldThrow(string? invalidLabel)
    {
        // Arrange
        var key = CreateValidSoftwareKey();

        // Act & Assert
        var act = () => key.UpdateLabel(invalidLabel!);
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void ClearDomainEvents_ShouldRemoveAllEvents()
    {
        // Arrange
        var key = CreateValidSoftwareKey();
        key.DomainEvents.Should().NotBeEmpty();

        // Act
        key.ClearDomainEvents();

        // Assert
        key.DomainEvents.Should().BeEmpty();
    }

    [Theory]
    [InlineData(KeyAlgorithm.KazSign256)]
    [InlineData(KeyAlgorithm.KazKem256)]
    [InlineData(KeyAlgorithm.MlDsa87)]
    public void CreateSoftwareKey_WithDifferentAlgorithms_ShouldSetCorrectAlgorithm(KeyAlgorithm algorithm)
    {
        // Arrange & Act
        var key = CryptoKey.CreateSoftwareKey(
            label: "Test",
            algorithm: algorithm,
            purpose: KeyPurpose.Signing,
            publicKey: new byte[2592],
            encryptedPrivateKey: new byte[5000],
            keyFingerprint: "fp");

        // Assert
        key.Algorithm.Should().Be(algorithm);
    }

    [Theory]
    [InlineData(KeyPurpose.Signing)]
    [InlineData(KeyPurpose.KeyEncapsulation)]
    [InlineData(KeyPurpose.DualUse)]
    public void CreateSoftwareKey_WithDifferentPurposes_ShouldSetCorrectPurpose(KeyPurpose purpose)
    {
        // Arrange & Act
        var key = CryptoKey.CreateSoftwareKey(
            label: "Test",
            algorithm: KeyAlgorithm.KazSign256,
            purpose: purpose,
            publicKey: new byte[2592],
            encryptedPrivateKey: new byte[5000],
            keyFingerprint: "fp");

        // Assert
        key.Purpose.Should().Be(purpose);
    }

    private static CryptoKey CreateValidSoftwareKey()
    {
        return CryptoKey.CreateSoftwareKey(
            label: "Test Key",
            algorithm: KeyAlgorithm.KazSign256,
            purpose: KeyPurpose.Signing,
            publicKey: new byte[2592],
            encryptedPrivateKey: new byte[5000],
            keyFingerprint: "test-fingerprint",
            expiresAt: DateTimeOffset.UtcNow.AddYears(1));
    }
}
