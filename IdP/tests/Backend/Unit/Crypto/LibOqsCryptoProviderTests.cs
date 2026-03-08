using FluentAssertions;
using PqcIdentity.Crypto.Domain.Enums;
using PqcIdentity.Crypto.Infrastructure.Providers;

namespace PqcIdentity.Tests.Unit.Crypto;

/// <summary>
/// Unit tests for LibOqsCryptoProvider.
/// </summary>
public class LibOqsCryptoProviderTests
{
    private readonly LibOqsCryptoProvider _sut = new();

    [Fact]
    public void SupportedAlgorithms_ShouldContainPqcAlgorithms()
    {
        // Act
        var supported = _sut.SupportedAlgorithms;

        // Assert
        supported.Should().Contain(KeyAlgorithm.MlDsa65);
        supported.Should().Contain(KeyAlgorithm.MlDsa87);
        supported.Should().Contain(KeyAlgorithm.MlKem768);
        supported.Should().Contain(KeyAlgorithm.MlKem1024);
    }

    [Theory]
    [InlineData(KeyAlgorithm.MlDsa65)]
    [InlineData(KeyAlgorithm.MlDsa87)]
    [InlineData(KeyAlgorithm.MlKem768)]
    [InlineData(KeyAlgorithm.MlKem1024)]
    public async Task GenerateKeyPairAsync_WithSupportedAlgorithm_ShouldReturnKeyPair(KeyAlgorithm algorithm)
    {
        // Act
        var result = await _sut.GenerateKeyPairAsync(algorithm);

        // Assert
        result.Should().NotBeNull();
        result.PublicKey.Should().NotBeEmpty();
        result.PrivateKey.Should().NotBeEmpty();
    }

    [Theory]
    [InlineData(KeyAlgorithm.MlDsa65, 1952)]  // ML-DSA-65 public key size
    [InlineData(KeyAlgorithm.MlDsa87, 2592)]  // ML-DSA-87 public key size
    [InlineData(KeyAlgorithm.MlKem768, 1184)] // ML-KEM-768 public key size
    [InlineData(KeyAlgorithm.MlKem1024, 1568)] // ML-KEM-1024 public key size
    public async Task GenerateKeyPairAsync_ShouldReturnCorrectPublicKeySize(KeyAlgorithm algorithm, int expectedSize)
    {
        // Act
        var result = await _sut.GenerateKeyPairAsync(algorithm);

        // Assert
        result.PublicKey.Length.Should().Be(expectedSize);
    }

    [Theory]
    [InlineData(KeyAlgorithm.MlDsa65, 4032)]  // ML-DSA-65 private key size
    [InlineData(KeyAlgorithm.MlDsa87, 4896)]  // ML-DSA-87 private key size
    [InlineData(KeyAlgorithm.MlKem768, 2400)] // ML-KEM-768 private key size
    [InlineData(KeyAlgorithm.MlKem1024, 3168)] // ML-KEM-1024 private key size
    public async Task GenerateKeyPairAsync_ShouldReturnCorrectPrivateKeySize(KeyAlgorithm algorithm, int expectedSize)
    {
        // Act
        var result = await _sut.GenerateKeyPairAsync(algorithm);

        // Assert
        result.PrivateKey.Length.Should().Be(expectedSize);
    }

    [Theory]
    [InlineData(KeyAlgorithm.KazSign256)]
    [InlineData(KeyAlgorithm.EcdsaP256)]
    public async Task GenerateKeyPairAsync_WithUnsupportedAlgorithm_ShouldThrow(KeyAlgorithm algorithm)
    {
        // Act
        var act = async () => await _sut.GenerateKeyPairAsync(algorithm);

        // Assert
        await act.Should().ThrowAsync<ArgumentException>();
    }

    [Theory]
    [InlineData(KeyAlgorithm.MlDsa65)]
    [InlineData(KeyAlgorithm.MlDsa87)]
    public async Task SignAsync_WithSigningAlgorithm_ShouldReturnSignature(KeyAlgorithm algorithm)
    {
        // Arrange
        var keyPair = await _sut.GenerateKeyPairAsync(algorithm);
        var data = "Test message to sign"u8.ToArray();

        // Act
        var signature = await _sut.SignAsync(data, keyPair.PrivateKey, algorithm);

        // Assert
        signature.Should().NotBeEmpty();
    }

    [Theory]
    [InlineData(KeyAlgorithm.MlDsa65, 3309)]  // ML-DSA-65 signature size
    [InlineData(KeyAlgorithm.MlDsa87, 4627)]  // ML-DSA-87 signature size
    public async Task SignAsync_ShouldReturnCorrectSignatureSize(KeyAlgorithm algorithm, int expectedSize)
    {
        // Arrange
        var keyPair = await _sut.GenerateKeyPairAsync(algorithm);
        var data = "Test message"u8.ToArray();

        // Act
        var signature = await _sut.SignAsync(data, keyPair.PrivateKey, algorithm);

        // Assert
        signature.Length.Should().Be(expectedSize);
    }

    [Theory]
    [InlineData(KeyAlgorithm.MlKem768)]
    [InlineData(KeyAlgorithm.MlKem1024)]
    public async Task SignAsync_WithKemAlgorithm_ShouldThrow(KeyAlgorithm algorithm)
    {
        // Arrange
        var data = "Test"u8.ToArray();
        var privateKey = new byte[100];

        // Act
        var act = async () => await _sut.SignAsync(data, privateKey, algorithm);

        // Assert
        await act.Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public async Task SignAsync_WithNullData_ShouldThrow()
    {
        // Arrange
        var privateKey = new byte[100];

        // Act
        var act = async () => await _sut.SignAsync(null!, privateKey, KeyAlgorithm.MlDsa65);

        // Assert
        await act.Should().ThrowAsync<ArgumentNullException>();
    }

    [Fact]
    public async Task SignAsync_WithNullPrivateKey_ShouldThrow()
    {
        // Arrange
        var data = "Test"u8.ToArray();

        // Act
        var act = async () => await _sut.SignAsync(data, null!, KeyAlgorithm.MlDsa65);

        // Assert
        await act.Should().ThrowAsync<ArgumentNullException>();
    }

    [Theory]
    [InlineData(KeyAlgorithm.MlDsa65)]
    [InlineData(KeyAlgorithm.MlDsa87)]
    public async Task VerifyAsync_WithValidSignature_ShouldReturnTrue(KeyAlgorithm algorithm)
    {
        // Arrange
        var keyPair = await _sut.GenerateKeyPairAsync(algorithm);
        var data = "Test message"u8.ToArray();
        var signature = await _sut.SignAsync(data, keyPair.PrivateKey, algorithm);

        // Act
        var isValid = await _sut.VerifyAsync(data, signature, keyPair.PublicKey, algorithm);

        // Assert
        // Note: The placeholder implementation always returns true
        isValid.Should().BeTrue();
    }

    [Fact]
    public async Task VerifyAsync_WithNullData_ShouldThrow()
    {
        // Arrange
        var publicKey = new byte[100];
        var signature = new byte[100];

        // Act
        var act = async () => await _sut.VerifyAsync(null!, signature, publicKey, KeyAlgorithm.MlDsa65);

        // Assert
        await act.Should().ThrowAsync<ArgumentNullException>();
    }

    [Theory]
    [InlineData(KeyAlgorithm.MlKem768)]
    [InlineData(KeyAlgorithm.MlKem1024)]
    public async Task EncapsulateAsync_WithKemAlgorithm_ShouldReturnResult(KeyAlgorithm algorithm)
    {
        // Arrange
        var keyPair = await _sut.GenerateKeyPairAsync(algorithm);

        // Act
        var result = await _sut.EncapsulateAsync(keyPair.PublicKey, algorithm);

        // Assert
        result.Should().NotBeNull();
        result.Ciphertext.Should().NotBeEmpty();
        result.SharedSecret.Should().NotBeEmpty();
    }

    [Theory]
    [InlineData(KeyAlgorithm.MlKem768, 1088)]  // ML-KEM-768 ciphertext size
    [InlineData(KeyAlgorithm.MlKem1024, 1568)] // ML-KEM-1024 ciphertext size
    public async Task EncapsulateAsync_ShouldReturnCorrectCiphertextSize(KeyAlgorithm algorithm, int expectedSize)
    {
        // Arrange
        var keyPair = await _sut.GenerateKeyPairAsync(algorithm);

        // Act
        var result = await _sut.EncapsulateAsync(keyPair.PublicKey, algorithm);

        // Assert
        result.Ciphertext.Length.Should().Be(expectedSize);
    }

    [Theory]
    [InlineData(KeyAlgorithm.MlKem768)]
    [InlineData(KeyAlgorithm.MlKem1024)]
    public async Task EncapsulateAsync_ShouldReturnSharedSecretOfCorrectSize(KeyAlgorithm algorithm)
    {
        // Arrange
        var keyPair = await _sut.GenerateKeyPairAsync(algorithm);

        // Act
        var result = await _sut.EncapsulateAsync(keyPair.PublicKey, algorithm);

        // Assert
        result.SharedSecret.Length.Should().Be(32); // 32 bytes for both KEM algorithms
    }

    [Theory]
    [InlineData(KeyAlgorithm.MlDsa65)]
    [InlineData(KeyAlgorithm.MlDsa87)]
    public async Task EncapsulateAsync_WithSigningAlgorithm_ShouldThrow(KeyAlgorithm algorithm)
    {
        // Arrange
        var publicKey = new byte[100];

        // Act
        var act = async () => await _sut.EncapsulateAsync(publicKey, algorithm);

        // Assert
        await act.Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public async Task EncapsulateAsync_WithNullPublicKey_ShouldThrow()
    {
        // Act
        var act = async () => await _sut.EncapsulateAsync(null!, KeyAlgorithm.MlKem768);

        // Assert
        await act.Should().ThrowAsync<ArgumentNullException>();
    }

    [Theory]
    [InlineData(KeyAlgorithm.MlKem768)]
    [InlineData(KeyAlgorithm.MlKem1024)]
    public async Task DecapsulateAsync_WithKemAlgorithm_ShouldReturnSharedSecret(KeyAlgorithm algorithm)
    {
        // Arrange
        var keyPair = await _sut.GenerateKeyPairAsync(algorithm);
        var encapResult = await _sut.EncapsulateAsync(keyPair.PublicKey, algorithm);

        // Act
        var sharedSecret = await _sut.DecapsulateAsync(encapResult.Ciphertext, keyPair.PrivateKey, algorithm);

        // Assert
        sharedSecret.Should().NotBeEmpty();
        sharedSecret.Length.Should().Be(32);
    }

    [Theory]
    [InlineData(KeyAlgorithm.MlDsa65)]
    [InlineData(KeyAlgorithm.MlDsa87)]
    public async Task DecapsulateAsync_WithSigningAlgorithm_ShouldThrow(KeyAlgorithm algorithm)
    {
        // Arrange
        var ciphertext = new byte[100];
        var privateKey = new byte[100];

        // Act
        var act = async () => await _sut.DecapsulateAsync(ciphertext, privateKey, algorithm);

        // Assert
        await act.Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public async Task DecapsulateAsync_WithNullCiphertext_ShouldThrow()
    {
        // Arrange
        var privateKey = new byte[100];

        // Act
        var act = async () => await _sut.DecapsulateAsync(null!, privateKey, KeyAlgorithm.MlKem768);

        // Assert
        await act.Should().ThrowAsync<ArgumentNullException>();
    }

    [Fact]
    public async Task DecapsulateAsync_WithNullPrivateKey_ShouldThrow()
    {
        // Arrange
        var ciphertext = new byte[100];

        // Act
        var act = async () => await _sut.DecapsulateAsync(ciphertext, null!, KeyAlgorithm.MlKem768);

        // Assert
        await act.Should().ThrowAsync<ArgumentNullException>();
    }

    [Fact]
    public void ComputeFingerprint_ShouldReturnHexString()
    {
        // Arrange
        var publicKey = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };

        // Act
        var fingerprint = _sut.ComputeFingerprint(publicKey);

        // Assert
        fingerprint.Should().NotBeNullOrEmpty();
        fingerprint.Should().MatchRegex("^[0-9a-f]{64}$"); // SHA-256 hex is 64 chars
    }

    [Fact]
    public void ComputeFingerprint_WithSameKey_ShouldReturnSameFingerprint()
    {
        // Arrange
        var publicKey = new byte[] { 1, 2, 3, 4, 5 };

        // Act
        var fingerprint1 = _sut.ComputeFingerprint(publicKey);
        var fingerprint2 = _sut.ComputeFingerprint(publicKey);

        // Assert
        fingerprint1.Should().Be(fingerprint2);
    }

    [Fact]
    public void ComputeFingerprint_WithDifferentKeys_ShouldReturnDifferentFingerprints()
    {
        // Arrange
        var key1 = new byte[] { 1, 2, 3 };
        var key2 = new byte[] { 4, 5, 6 };

        // Act
        var fingerprint1 = _sut.ComputeFingerprint(key1);
        var fingerprint2 = _sut.ComputeFingerprint(key2);

        // Assert
        fingerprint1.Should().NotBe(fingerprint2);
    }

    [Fact]
    public void ComputeFingerprint_WithNullKey_ShouldThrow()
    {
        // Act
        var act = () => _sut.ComputeFingerprint(null!);

        // Assert
        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void ComputeFingerprint_ShouldReturnLowercaseHex()
    {
        // Arrange
        var publicKey = new byte[] { 255, 128, 64, 32 }; // Values that would have uppercase in hex

        // Act
        var fingerprint = _sut.ComputeFingerprint(publicKey);

        // Assert
        fingerprint.Should().Be(fingerprint.ToLowerInvariant());
    }
}
