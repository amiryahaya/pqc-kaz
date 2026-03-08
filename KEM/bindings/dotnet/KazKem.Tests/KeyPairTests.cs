using System.Security.Cryptography;
using Xunit;
using Antrapol.Kaz.Kem;

namespace Antrapol.Kaz.Kem.Tests;

/// <summary>
/// Tests for key pair generation and management.
/// </summary>
public class KeyPairTests : IDisposable
{
    private KazKemContext _context;

    public KeyPairTests()
    {
        _context = KazKemContext.Initialize(SecurityLevel.Level128);
    }

    public void Dispose()
    {
        _context?.Dispose();
    }

    [Fact]
    public void GenerateKeyPair_ShouldReturnValidKeyPair()
    {
        // Act
        using var keyPair = _context.GenerateKeyPair();

        // Assert
        Assert.NotNull(keyPair);
        Assert.Equal(_context.PublicKeySize, keyPair.PublicKeySize);
        Assert.Equal(_context.PrivateKeySize, keyPair.PrivateKeySize);
    }

    [Fact]
    public void GenerateKeyPair_MultipleCalls_ShouldProduceDifferentKeys()
    {
        // Act
        using var keyPair1 = _context.GenerateKeyPair();
        using var keyPair2 = _context.GenerateKeyPair();
        using var keyPair3 = _context.GenerateKeyPair();

        // Assert - all should be unique
        Assert.NotEqual(keyPair1.PublicKey.ToArray(), keyPair2.PublicKey.ToArray());
        Assert.NotEqual(keyPair2.PublicKey.ToArray(), keyPair3.PublicKey.ToArray());
        Assert.NotEqual(keyPair1.PublicKey.ToArray(), keyPair3.PublicKey.ToArray());
    }

    [Fact]
    public void KeyPair_ExportPublicKey_ShouldReturnCopy()
    {
        // Arrange
        using var keyPair = _context.GenerateKeyPair();

        // Act
        var export1 = keyPair.ExportPublicKey();
        var export2 = keyPair.ExportPublicKey();

        // Assert - should be equal but different instances
        Assert.Equal(export1, export2);
        Assert.NotSame(export1, export2);
    }

    [Fact]
    public void KeyPair_ExportPrivateKey_ShouldReturnCopy()
    {
        // Arrange
        using var keyPair = _context.GenerateKeyPair();

        // Act
        var export1 = keyPair.ExportPrivateKey();
        var export2 = keyPair.ExportPrivateKey();

        // Assert
        Assert.Equal(export1, export2);
        Assert.NotSame(export1, export2);
    }

    [Fact]
    public void KeyPair_GetPublicKey_ShouldReturnValidPublicKey()
    {
        // Arrange
        using var keyPair = _context.GenerateKeyPair();

        // Act
        var publicKey = keyPair.GetPublicKey();

        // Assert
        Assert.NotNull(publicKey);
        Assert.Equal(keyPair.PublicKeySize, publicKey.Size);
        Assert.Equal(keyPair.PublicKey.ToArray(), publicKey.Bytes.ToArray());
    }

    [Fact]
    public void KeyPair_SecurityLevel_ShouldMatchContext()
    {
        // Act
        using var keyPair = _context.GenerateKeyPair();

        // Assert
        Assert.Equal(_context.SecurityLevel, keyPair.SecurityLevel);
    }

    [Fact]
    public void KeyPair_AfterDispose_ShouldThrowOnAccess()
    {
        // Arrange
        var keyPair = _context.GenerateKeyPair();
        keyPair.Dispose();

        // Act & Assert
        Assert.Throws<ObjectDisposedException>(() => keyPair.PublicKey.ToArray());
        Assert.Throws<ObjectDisposedException>(() => keyPair.PrivateKey.ToArray());
        Assert.Throws<ObjectDisposedException>(() => keyPair.ExportPublicKey());
        Assert.Throws<ObjectDisposedException>(() => keyPair.ExportPrivateKey());
        Assert.Throws<ObjectDisposedException>(() => keyPair.GetPublicKey());
    }

    [Fact]
    public void KeyPair_DoubleDispose_ShouldNotThrow()
    {
        // Arrange
        var keyPair = _context.GenerateKeyPair();

        // Act & Assert - should not throw
        keyPair.Dispose();
        keyPair.Dispose();
    }

    [Fact]
    public void PublicKey_FromBytes_ShouldCreateValidPublicKey()
    {
        // Arrange
        using var keyPair = _context.GenerateKeyPair();
        var bytes = keyPair.ExportPublicKey();

        // Act
        var publicKey = KazKemPublicKey.FromBytes(bytes, SecurityLevel.Level128);

        // Assert
        Assert.NotNull(publicKey);
        Assert.Equal(bytes, publicKey.Export());
    }

    [Fact]
    public void PublicKey_Export_ShouldReturnCopy()
    {
        // Arrange
        using var keyPair = _context.GenerateKeyPair();
        var publicKey = keyPair.GetPublicKey();

        // Act
        var export1 = publicKey.Export();
        var export2 = publicKey.Export();

        // Assert
        Assert.Equal(export1, export2);
        Assert.NotSame(export1, export2);
    }

    [Theory]
    [InlineData(SecurityLevel.Level128)]
    [InlineData(SecurityLevel.Level192)]
    [InlineData(SecurityLevel.Level256)]
    public void GenerateKeyPair_AllLevels_ShouldWork(SecurityLevel level)
    {
        // Reinitialize for different level
        _context.Dispose();
        _context = KazKemContext.Initialize(level);

        // Act
        using var keyPair = _context.GenerateKeyPair();

        // Assert
        Assert.Equal(level, keyPair.SecurityLevel);
        Assert.Equal(_context.PublicKeySize, keyPair.PublicKeySize);
        Assert.Equal(_context.PrivateKeySize, keyPair.PrivateKeySize);
    }
}
