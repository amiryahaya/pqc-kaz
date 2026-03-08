using System.Security.Cryptography;
using Xunit;
using Antrapol.Kaz.Kem;

namespace Antrapol.Kaz.Kem.Tests;

/// <summary>
/// Tests for encapsulation and decapsulation operations.
/// </summary>
public class EncapsulationTests : IDisposable
{
    private KazKemContext _context;
    private KazKemKeyPair _keyPair;

    public EncapsulationTests()
    {
        _context = KazKemContext.Initialize(SecurityLevel.Level128);
        _keyPair = _context.GenerateKeyPair();
    }

    public void Dispose()
    {
        _keyPair?.Dispose();
        _context?.Dispose();
    }

    [Fact]
    public void Encapsulate_ShouldReturnValidResult()
    {
        // Act
        using var result = _context.Encapsulate(_keyPair.GetPublicKey());

        // Assert
        Assert.NotNull(result);
        Assert.True(result.CiphertextSize > 0);
        Assert.True(result.SharedSecretSize > 0);
    }

    [Fact]
    public void Encapsulate_WithBytes_ShouldReturnValidResult()
    {
        // Arrange
        var publicKeyBytes = _keyPair.ExportPublicKey();

        // Act
        using var result = _context.Encapsulate(publicKeyBytes);

        // Assert
        Assert.NotNull(result);
        Assert.True(result.CiphertextSize > 0);
    }

    [Fact]
    public void EncapsulateDecapsulate_ShouldProduceSameSecret()
    {
        // Act
        using var encResult = _context.Encapsulate(_keyPair.GetPublicKey());
        var decapsulatedSecret = _context.Decapsulate(encResult.Ciphertext, _keyPair);

        // Assert
        Assert.Equal(encResult.SharedSecret.ToArray(), decapsulatedSecret);
    }

    [Fact]
    public void Decapsulate_WithPrivateKeyBytes_ShouldWork()
    {
        // Arrange
        using var encResult = _context.Encapsulate(_keyPair.GetPublicKey());
        var privateKeyBytes = _keyPair.ExportPrivateKey();

        // Act
        var decapsulatedSecret = _context.Decapsulate(encResult.Ciphertext, privateKeyBytes);

        // Assert
        Assert.Equal(encResult.SharedSecret.ToArray(), decapsulatedSecret);
    }

    [Fact]
    public void Encapsulate_MultipleTimes_ShouldProduceDifferentResults()
    {
        // Act
        using var result1 = _context.Encapsulate(_keyPair.GetPublicKey());
        using var result2 = _context.Encapsulate(_keyPair.GetPublicKey());
        using var result3 = _context.Encapsulate(_keyPair.GetPublicKey());

        // Assert - ciphertexts should be different
        Assert.NotEqual(result1.Ciphertext.ToArray(), result2.Ciphertext.ToArray());
        Assert.NotEqual(result2.Ciphertext.ToArray(), result3.Ciphertext.ToArray());

        // Shared secrets should also be different
        Assert.NotEqual(result1.SharedSecret.ToArray(), result2.SharedSecret.ToArray());
    }

    [Fact]
    public void Decapsulate_WrongPrivateKey_ShouldProduceDifferentSecret()
    {
        // Arrange
        using var wrongKeyPair = _context.GenerateKeyPair();
        using var encResult = _context.Encapsulate(_keyPair.GetPublicKey());

        // Act
        var wrongSecret = _context.Decapsulate(encResult.Ciphertext, wrongKeyPair);

        // Assert - should NOT match
        Assert.NotEqual(encResult.SharedSecret.ToArray(), wrongSecret);
    }

    [Fact]
    public void Encapsulate_WithWrongSizePublicKey_ShouldThrow()
    {
        // Arrange
        var wrongSizeKey = new byte[16]; // Too small

        // Act & Assert
        var ex = Assert.Throws<ArgumentException>(() => _context.Encapsulate(wrongSizeKey));
        Assert.Contains("Public key", ex.Message);
    }

    [Fact]
    public void Encapsulate_WithNullPublicKey_ShouldThrow()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => _context.Encapsulate((KazKemPublicKey)null!));
    }

    [Fact]
    public void Decapsulate_WithWrongSizePrivateKey_ShouldThrow()
    {
        // Arrange
        using var encResult = _context.Encapsulate(_keyPair.GetPublicKey());
        var wrongSizeKey = new byte[16]; // Too small

        // Act & Assert
        var ex = Assert.Throws<ArgumentException>(() =>
            _context.Decapsulate(encResult.Ciphertext, wrongSizeKey));
        Assert.Contains("Private key", ex.Message);
    }

    [Fact]
    public void Decapsulate_WithNullKeyPair_ShouldThrow()
    {
        // Arrange
        using var encResult = _context.Encapsulate(_keyPair.GetPublicKey());

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            _context.Decapsulate(encResult.Ciphertext, (KazKemKeyPair)null!));
    }

    [Fact]
    public void EncapsulationResult_ExportCiphertext_ShouldReturnCopy()
    {
        // Arrange
        using var result = _context.Encapsulate(_keyPair.GetPublicKey());

        // Act
        var export1 = result.ExportCiphertext();
        var export2 = result.ExportCiphertext();

        // Assert
        Assert.Equal(export1, export2);
        Assert.NotSame(export1, export2);
    }

    [Fact]
    public void EncapsulationResult_ExportSharedSecret_ShouldReturnCopy()
    {
        // Arrange
        using var result = _context.Encapsulate(_keyPair.GetPublicKey());

        // Act
        var export1 = result.ExportSharedSecret();
        var export2 = result.ExportSharedSecret();

        // Assert
        Assert.Equal(export1, export2);
        Assert.NotSame(export1, export2);
    }

    [Fact]
    public void EncapsulationResult_AfterDispose_ShouldThrowOnAccess()
    {
        // Arrange
        var result = _context.Encapsulate(_keyPair.GetPublicKey());
        result.Dispose();

        // Act & Assert
        Assert.Throws<ObjectDisposedException>(() => result.Ciphertext.ToArray());
        Assert.Throws<ObjectDisposedException>(() => result.SharedSecret.ToArray());
        Assert.Throws<ObjectDisposedException>(() => result.ExportCiphertext());
        Assert.Throws<ObjectDisposedException>(() => result.ExportSharedSecret());
    }

    [Fact]
    public void EncapsulationResult_DoubleDispose_ShouldNotThrow()
    {
        // Arrange
        var result = _context.Encapsulate(_keyPair.GetPublicKey());

        // Act & Assert - should not throw
        result.Dispose();
        result.Dispose();
    }

    [Theory]
    [InlineData(SecurityLevel.Level128)]
    [InlineData(SecurityLevel.Level192)]
    [InlineData(SecurityLevel.Level256)]
    public void EncapsulateDecapsulate_AllLevels_ShouldWork(SecurityLevel level)
    {
        // Reinitialize for different level
        _keyPair.Dispose();
        _context.Dispose();
        _context = KazKemContext.Initialize(level);
        _keyPair = _context.GenerateKeyPair();

        // Act
        using var encResult = _context.Encapsulate(_keyPair.GetPublicKey());
        var decapsulatedSecret = _context.Decapsulate(encResult.Ciphertext, _keyPair);

        // Assert
        Assert.Equal(encResult.SharedSecret.ToArray(), decapsulatedSecret);
    }

    [Fact]
    public void Encapsulate_AfterContextDispose_ShouldThrow()
    {
        // Arrange
        var publicKey = _keyPair.GetPublicKey();
        _context.Dispose();

        // Act & Assert
        Assert.Throws<ObjectDisposedException>(() =>
            _context.Encapsulate(publicKey));
    }

    [Fact]
    public void Decapsulate_AfterContextDispose_ShouldThrow()
    {
        // Arrange
        using var encResult = _context.Encapsulate(_keyPair.GetPublicKey());
        var ciphertext = encResult.ExportCiphertext();
        _context.Dispose();

        // Act & Assert
        Assert.Throws<ObjectDisposedException>(() =>
            _context.Decapsulate(ciphertext, _keyPair));
    }
}
