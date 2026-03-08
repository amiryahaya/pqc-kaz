using FluentAssertions;
using PqcIdentity.Identity.Domain.Entities;

namespace PqcIdentity.Tests.Unit.Identity;

/// <summary>
/// Unit tests for KeyShare entity.
/// </summary>
public class KeyShareTests
{
    [Fact]
    public void CreateControlShare_WithValidData_ShouldCreateKeyShare()
    {
        // Arrange
        var registrationId = Guid.CreateVersion7();
        var encryptedData = new byte[] { 1, 2, 3, 4, 5 };
        var encapsulatedKey = new byte[] { 10, 20, 30 };
        var shareIndex = 1;

        // Act
        var keyShare = KeyShare.CreateControlShare(
            registrationId: registrationId,
            encryptedData: encryptedData,
            encapsulatedKey: encapsulatedKey,
            shareIndex: shareIndex);

        // Assert
        keyShare.Should().NotBeNull();
        keyShare.Id.Should().NotBeEmpty();
        keyShare.RegistrationId.Should().Be(registrationId);
        keyShare.UserId.Should().BeNull(); // Not linked to user yet
        keyShare.Type.Should().Be(KeyShareType.Control);
        keyShare.EncryptedData.Should().BeEquivalentTo(encryptedData);
        keyShare.EncapsulatedKey.Should().BeEquivalentTo(encapsulatedKey);
        keyShare.ShareIndex.Should().Be(shareIndex);
        keyShare.IsActive.Should().BeTrue();
    }

    [Fact]
    public void CreateRecoveryShare_WithValidData_ShouldCreateKeyShare()
    {
        // Arrange
        var registrationId = Guid.CreateVersion7();
        var encryptedData = new byte[] { 1, 2, 3, 4, 5 };
        var nonce = new byte[] { 10, 20, 30 };
        var authTag = new byte[] { 40, 50, 60 };
        var salt = new byte[] { 70, 80, 90 };
        var shareIndex = 2;

        // Act
        var keyShare = KeyShare.CreateRecoveryShare(
            registrationId: registrationId,
            encryptedData: encryptedData,
            nonce: nonce,
            authTag: authTag,
            salt: salt,
            shareIndex: shareIndex);

        // Assert
        keyShare.Should().NotBeNull();
        keyShare.Id.Should().NotBeEmpty();
        keyShare.RegistrationId.Should().Be(registrationId);
        keyShare.UserId.Should().BeNull(); // Not linked to user yet
        keyShare.Type.Should().Be(KeyShareType.Recovery);
        keyShare.EncryptedData.Should().BeEquivalentTo(encryptedData);
        keyShare.Nonce.Should().BeEquivalentTo(nonce);
        keyShare.AuthTag.Should().BeEquivalentTo(authTag);
        keyShare.Salt.Should().BeEquivalentTo(salt);
        keyShare.ShareIndex.Should().Be(shareIndex);
        keyShare.IsActive.Should().BeTrue();
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public void CreateControlShare_WithDifferentShareIndices_ShouldSetCorrectIndex(int shareIndex)
    {
        // Arrange & Act
        var keyShare = KeyShare.CreateControlShare(
            registrationId: Guid.CreateVersion7(),
            encryptedData: [1, 2, 3],
            encapsulatedKey: [4, 5, 6],
            shareIndex: shareIndex);

        // Assert
        keyShare.ShareIndex.Should().Be(shareIndex);
    }

    [Fact]
    public void Deactivate_ShouldSetIsActiveToFalse()
    {
        // Arrange
        var keyShare = CreateControlShare();
        keyShare.IsActive.Should().BeTrue();

        // Act
        keyShare.Deactivate();

        // Assert
        keyShare.IsActive.Should().BeFalse();
    }

    [Fact]
    public void UpdateEncryptedData_ShouldReplaceData()
    {
        // Arrange
        var keyShare = CreateControlShare();
        var newData = new byte[] { 99, 98, 97 };

        // Act
        keyShare.UpdateEncryptedData(newData);

        // Assert
        keyShare.EncryptedData.Should().BeEquivalentTo(newData);
    }

    [Fact]
    public void UpdateEncryptedData_WithNonceAndAuthTag_ShouldReplaceAll()
    {
        // Arrange
        var keyShare = CreateRecoveryShare();
        var newData = new byte[] { 99, 98, 97 };
        var newNonce = new byte[] { 88, 87, 86 };
        var newAuthTag = new byte[] { 77, 76, 75 };
        var newSalt = new byte[] { 66, 65, 64 };

        // Act
        keyShare.UpdateEncryptedData(newData, newNonce, newAuthTag, newSalt);

        // Assert
        keyShare.EncryptedData.Should().BeEquivalentTo(newData);
        keyShare.Nonce.Should().BeEquivalentTo(newNonce);
        keyShare.AuthTag.Should().BeEquivalentTo(newAuthTag);
        keyShare.Salt.Should().BeEquivalentTo(newSalt);
    }

    [Fact]
    public void CreateControlShare_ShouldHaveNullNonceAndAuthTag()
    {
        // Arrange & Act
        var keyShare = CreateControlShare();

        // Assert
        keyShare.Nonce.Should().BeNull();
        keyShare.AuthTag.Should().BeNull();
        keyShare.Salt.Should().BeNull();
        keyShare.EncapsulatedKey.Should().NotBeNull();
    }

    [Fact]
    public void CreateRecoveryShare_ShouldHaveNullEncapsulatedKey()
    {
        // Arrange & Act
        var keyShare = CreateRecoveryShare();

        // Assert
        keyShare.EncapsulatedKey.Should().BeNull();
        keyShare.Nonce.Should().NotBeNull();
        keyShare.AuthTag.Should().NotBeNull();
        keyShare.Salt.Should().NotBeNull();
    }

    [Fact]
    public void LinkToUser_WhenNotLinked_ShouldLinkSuccessfully()
    {
        // Arrange
        var keyShare = CreateControlShare();
        var userId = Guid.CreateVersion7();

        // Act
        keyShare.LinkToUser(userId);

        // Assert
        keyShare.UserId.Should().Be(userId);
    }

    [Fact]
    public void LinkToUser_WhenAlreadyLinked_ShouldThrow()
    {
        // Arrange
        var keyShare = CreateControlShare();
        var userId = Guid.CreateVersion7();
        keyShare.LinkToUser(userId);

        // Act
        var act = () => keyShare.LinkToUser(Guid.CreateVersion7());

        // Assert
        act.Should().Throw<InvalidOperationException>()
            .WithMessage("Key share is already linked to a user.");
    }

    private static KeyShare CreateControlShare()
    {
        return KeyShare.CreateControlShare(
            registrationId: Guid.CreateVersion7(),
            encryptedData: [1, 2, 3, 4, 5],
            encapsulatedKey: [10, 20, 30],
            shareIndex: 1);
    }

    private static KeyShare CreateRecoveryShare()
    {
        return KeyShare.CreateRecoveryShare(
            registrationId: Guid.CreateVersion7(),
            encryptedData: [1, 2, 3, 4, 5],
            nonce: [10, 20, 30],
            authTag: [40, 50, 60],
            salt: [70, 80, 90],
            shareIndex: 2);
    }
}
