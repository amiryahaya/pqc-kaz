using Xunit;
using Antrapol.Kaz.Kem;

namespace Antrapol.Kaz.Kem.Tests;

/// <summary>
/// Unit tests for KAZ-KEM .NET bindings.
/// </summary>
public class KazKemContextTests : IDisposable
{
    private KazKemContext? _context;

    public void Dispose()
    {
        _context?.Dispose();
    }

    [Fact]
    public void Initialize_WithLevel128_ShouldSucceed()
    {
        // Act
        _context = KazKemContext.Initialize(SecurityLevel.Level128);

        // Assert
        Assert.NotNull(_context);
        Assert.Equal(SecurityLevel.Level128, _context.SecurityLevel);
        Assert.True(KazKemContext.IsInitialized);
    }

    [Fact]
    public void Initialize_WithLevel192_ShouldSucceed()
    {
        // Act
        _context = KazKemContext.Initialize(SecurityLevel.Level192);

        // Assert
        Assert.NotNull(_context);
        Assert.Equal(SecurityLevel.Level192, _context.SecurityLevel);
    }

    [Fact]
    public void Initialize_WithLevel256_ShouldSucceed()
    {
        // Act
        _context = KazKemContext.Initialize(SecurityLevel.Level256);

        // Assert
        Assert.NotNull(_context);
        Assert.Equal(SecurityLevel.Level256, _context.SecurityLevel);
    }

    [Fact]
    public void Version_ShouldReturnVersionString()
    {
        // Act
        var version = KazKemContext.Version;

        // Assert
        Assert.NotNull(version);
        Assert.Contains("2.1", version);
    }

    [Fact]
    public void GenerateKeyPair_ShouldReturnValidKeys()
    {
        // Arrange
        _context = KazKemContext.Initialize(SecurityLevel.Level128);

        // Act
        using var keyPair = _context.GenerateKeyPair();

        // Assert
        Assert.NotNull(keyPair);
        Assert.Equal(_context.PublicKeySize, keyPair.PublicKeySize);
        Assert.Equal(_context.PrivateKeySize, keyPair.PrivateKeySize);
        Assert.Equal(SecurityLevel.Level128, keyPair.SecurityLevel);
    }

    [Fact]
    public void EncapsulateDecapsulate_ShouldProduceSameSharedSecret()
    {
        // Arrange
        _context = KazKemContext.Initialize(SecurityLevel.Level128);
        using var keyPair = _context.GenerateKeyPair();

        // Act
        using var encResult = _context.Encapsulate(keyPair.GetPublicKey());
        var decapsulatedSecret = _context.Decapsulate(encResult.Ciphertext, keyPair);

        // Assert
        Assert.Equal(encResult.SharedSecret.ToArray(), decapsulatedSecret);
    }

    [Fact]
    public void EncapsulateDecapsulate_WithLevel192_ShouldWork()
    {
        // Arrange
        _context = KazKemContext.Initialize(SecurityLevel.Level192);
        using var keyPair = _context.GenerateKeyPair();

        // Act
        using var encResult = _context.Encapsulate(keyPair.GetPublicKey());
        var decapsulatedSecret = _context.Decapsulate(encResult.Ciphertext, keyPair);

        // Assert
        Assert.Equal(encResult.SharedSecret.ToArray(), decapsulatedSecret);
    }

    [Fact]
    public void EncapsulateDecapsulate_WithLevel256_ShouldWork()
    {
        // Arrange
        _context = KazKemContext.Initialize(SecurityLevel.Level256);
        using var keyPair = _context.GenerateKeyPair();

        // Act
        using var encResult = _context.Encapsulate(keyPair.GetPublicKey());
        var decapsulatedSecret = _context.Decapsulate(encResult.Ciphertext, keyPair);

        // Assert
        Assert.Equal(encResult.SharedSecret.ToArray(), decapsulatedSecret);
    }

    [Fact]
    public void MultipleKeyPairs_ShouldBeUnique()
    {
        // Arrange
        _context = KazKemContext.Initialize(SecurityLevel.Level128);

        // Act
        using var keyPair1 = _context.GenerateKeyPair();
        using var keyPair2 = _context.GenerateKeyPair();

        // Assert - keys should be different
        Assert.NotEqual(keyPair1.PublicKey.ToArray(), keyPair2.PublicKey.ToArray());
        Assert.NotEqual(keyPair1.PrivateKey.ToArray(), keyPair2.PrivateKey.ToArray());
    }

    [Fact]
    public void WrongPrivateKey_ShouldNotDecapsulateCorrectly()
    {
        // Arrange
        _context = KazKemContext.Initialize(SecurityLevel.Level128);
        using var keyPair1 = _context.GenerateKeyPair();
        using var keyPair2 = _context.GenerateKeyPair();

        // Act - encapsulate with keyPair1's public key
        using var encResult = _context.Encapsulate(keyPair1.GetPublicKey());

        // Try to decapsulate with keyPair2's private key
        var wrongSecret = _context.Decapsulate(encResult.Ciphertext, keyPair2);

        // Assert - should produce different secret
        Assert.NotEqual(encResult.SharedSecret.ToArray(), wrongSecret);
    }

    [Fact]
    public void Encapsulate_WithWrongSizePublicKey_ShouldThrow()
    {
        // Arrange
        _context = KazKemContext.Initialize(SecurityLevel.Level128);
        var wrongSizeKey = new byte[16]; // Too small

        // Act & Assert
        Assert.Throws<ArgumentException>(() => _context.Encapsulate(wrongSizeKey));
    }

    [Fact]
    public void Dispose_ShouldCleanupContext()
    {
        // Arrange
        _context = KazKemContext.Initialize(SecurityLevel.Level128);

        // Act
        _context.Dispose();

        // Assert
        Assert.False(KazKemContext.IsInitialized);
    }

    [Fact]
    public void KeyPair_ExportMethods_ShouldWork()
    {
        // Arrange
        _context = KazKemContext.Initialize(SecurityLevel.Level128);
        using var keyPair = _context.GenerateKeyPair();

        // Act
        var exportedPk = keyPair.ExportPublicKey();
        var exportedSk = keyPair.ExportPrivateKey();
        var publicKey = keyPair.GetPublicKey();

        // Assert
        Assert.Equal(keyPair.PublicKey.ToArray(), exportedPk);
        Assert.Equal(keyPair.PrivateKey.ToArray(), exportedSk);
        Assert.Equal(keyPair.PublicKey.ToArray(), publicKey.Export());
    }

    [Fact]
    public void EncapsulationResult_ExportMethods_ShouldWork()
    {
        // Arrange
        _context = KazKemContext.Initialize(SecurityLevel.Level128);
        using var keyPair = _context.GenerateKeyPair();

        // Act
        using var encResult = _context.Encapsulate(keyPair.GetPublicKey());
        var exportedCt = encResult.ExportCiphertext();
        var exportedSs = encResult.ExportSharedSecret();

        // Assert
        Assert.Equal(encResult.Ciphertext.ToArray(), exportedCt);
        Assert.Equal(encResult.SharedSecret.ToArray(), exportedSs);
    }
}
