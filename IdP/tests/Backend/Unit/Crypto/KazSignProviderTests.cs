using FluentAssertions;
using PqcIdentity.Crypto.Infrastructure.Providers;

namespace PqcIdentity.Tests.Unit.Crypto;

/// <summary>
/// Unit tests for KazSignProvider.
/// Note: These tests verify the argument validation and API contract.
/// Integration tests with the native library are separate.
/// </summary>
public class KazSignProviderTests
{
    private readonly KazSignProvider _sut = new();

    // Key sizes from the public API
    private const int PublicKeySize = 2592;
    private const int SecretKeySize = 4896;

    [Fact]
    public void Sign_WithNullSecretKey_ShouldThrow()
    {
        // Arrange
        var message = "Test message"u8.ToArray();

        // Act
        var act = () => _sut.Sign(null!, message);

        // Assert
        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Sign_WithNullMessage_ShouldThrow()
    {
        // Arrange
        var secretKey = new byte[SecretKeySize];

        // Act
        var act = () => _sut.Sign(secretKey, null!);

        // Assert
        act.Should().Throw<ArgumentNullException>();
    }

    [Theory]
    [InlineData(0)]
    [InlineData(100)]
    [InlineData(4895)]  // One less than required
    [InlineData(4897)]  // One more than required
    public void Sign_WithInvalidSecretKeySize_ShouldThrow(int keySize)
    {
        // Arrange
        var secretKey = new byte[keySize];
        var message = "Test message"u8.ToArray();

        // Act
        var act = () => _sut.Sign(secretKey, message);

        // Assert
        act.Should().Throw<ArgumentException>()
            .WithMessage($"Invalid secret key size. Expected {SecretKeySize}, got {keySize}*");
    }

    [Fact]
    public void Verify_WithNullPublicKey_ShouldThrow()
    {
        // Arrange
        var message = "Test"u8.ToArray();
        var signature = new byte[100];

        // Act
        var act = () => _sut.Verify(null!, message, signature);

        // Assert
        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Verify_WithNullMessage_ShouldThrow()
    {
        // Arrange
        var publicKey = new byte[PublicKeySize];
        var signature = new byte[100];

        // Act
        var act = () => _sut.Verify(publicKey, null!, signature);

        // Assert
        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Verify_WithNullSignature_ShouldThrow()
    {
        // Arrange
        var publicKey = new byte[PublicKeySize];
        var message = "Test"u8.ToArray();

        // Act
        var act = () => _sut.Verify(publicKey, message, null!);

        // Assert
        act.Should().Throw<ArgumentNullException>();
    }

    [Theory]
    [InlineData(0)]
    [InlineData(100)]
    [InlineData(2591)]  // One less than required
    [InlineData(2593)]  // One more than required
    public void Verify_WithInvalidPublicKeySize_ShouldThrow(int keySize)
    {
        // Arrange
        var publicKey = new byte[keySize];
        var message = "Test"u8.ToArray();
        var signature = new byte[100];

        // Act
        var act = () => _sut.Verify(publicKey, message, signature);

        // Assert
        act.Should().Throw<ArgumentException>()
            .WithMessage($"Invalid public key size. Expected {PublicKeySize}, got {keySize}*");
    }
}

/// <summary>
/// Tests for KazSignKeyPair record.
/// </summary>
public class KazSignKeyPairTests
{
    [Fact]
    public void Create_WithValidData_ShouldStoreKeys()
    {
        // Arrange
        var publicKey = new byte[] { 1, 2, 3 };
        var secretKey = new byte[] { 4, 5, 6 };

        // Act
        var keyPair = new KazSignKeyPair(publicKey, secretKey);

        // Assert
        keyPair.PublicKey.Should().BeEquivalentTo(publicKey);
        keyPair.SecretKey.Should().BeEquivalentTo(secretKey);
    }

    [Fact]
    public void Equals_WithSameKeys_ShouldBeEqual()
    {
        // Arrange
        var publicKey = new byte[] { 1, 2, 3 };
        var secretKey = new byte[] { 4, 5, 6 };
        var keyPair1 = new KazSignKeyPair(publicKey, secretKey);
        var keyPair2 = new KazSignKeyPair(publicKey, secretKey);

        // Act & Assert
        keyPair1.Should().Be(keyPair2);
    }
}

/// <summary>
/// Tests for CryptographicException.
/// </summary>
public class CryptographicExceptionTests
{
    [Fact]
    public void Constructor_WithMessage_ShouldSetMessage()
    {
        // Arrange
        var message = "Test error message";

        // Act
        var exception = new CryptographicException(message);

        // Assert
        exception.Message.Should().Be(message);
    }

    [Fact]
    public void Constructor_WithMessageAndInner_ShouldSetBoth()
    {
        // Arrange
        var message = "Outer error";
        var innerException = new InvalidOperationException("Inner error");

        // Act
        var exception = new CryptographicException(message, innerException);

        // Assert
        exception.Message.Should().Be(message);
        exception.InnerException.Should().Be(innerException);
    }
}
