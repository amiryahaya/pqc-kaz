using Xunit;
using Antrapol.Kaz.Kem;

namespace Antrapol.Kaz.Kem.Tests;

/// <summary>
/// Tests for exception handling and error scenarios.
/// </summary>
public class ExceptionTests : IDisposable
{
    private KazKemContext? _context;

    public void Dispose()
    {
        _context?.Dispose();
    }

    [Fact]
    public void KazKemException_ShouldContainErrorCode()
    {
        // Arrange
        var exception = new KazKemException("Test error", -5);

        // Assert
        Assert.Equal(-5, exception.ErrorCode);
        Assert.Contains("Test error", exception.Message);
    }

    [Fact]
    public void KazKemException_DefaultErrorCode_ShouldBeMinusOne()
    {
        // Arrange
        var exception = new KazKemException("Test error");

        // Assert
        Assert.Equal(-1, exception.ErrorCode);
    }

    [Fact]
    public void KazKemException_WithInnerException_ShouldPreserveIt()
    {
        // Arrange
        var inner = new InvalidOperationException("Inner error");
        var exception = new KazKemException("Outer error", inner);

        // Assert
        Assert.Same(inner, exception.InnerException);
        Assert.Equal(-1, exception.ErrorCode);
    }

    [Fact]
    public void KazKemNotInitializedException_ShouldHaveCorrectErrorCode()
    {
        // Arrange
        var exception = new KazKemNotInitializedException();

        // Assert
        Assert.Equal(-6, exception.ErrorCode);
        Assert.Contains("not initialized", exception.Message.ToLower());
    }

    [Fact]
    public void InvalidSecurityLevelException_WithInt_ShouldHaveCorrectMessage()
    {
        // Arrange
        var exception = new InvalidSecurityLevelException(999);

        // Assert
        Assert.Equal(-7, exception.ErrorCode);
        Assert.Contains("999", exception.Message);
        Assert.Contains("128", exception.Message);
        Assert.Contains("192", exception.Message);
        Assert.Contains("256", exception.Message);
        Assert.Null(exception.AttemptedLevel);
    }

    [Fact]
    public void InvalidSecurityLevelException_WithSecurityLevel_ShouldHaveAttemptedLevel()
    {
        // Arrange
        var exception = new InvalidSecurityLevelException(SecurityLevel.Level128);

        // Assert
        Assert.Equal(-7, exception.ErrorCode);
        Assert.Equal(SecurityLevel.Level128, exception.AttemptedLevel);
    }

    [Fact]
    public void Current_WhenNotInitialized_ShouldThrowNotInitializedException()
    {
        // Ensure not initialized
        if (KazKemContext.IsInitialized)
        {
            KazKemContext.Current.Dispose();
        }

        // Act & Assert
        var exception = Assert.Throws<KazKemNotInitializedException>(() => KazKemContext.Current);
        Assert.Equal(-6, exception.ErrorCode);
    }

    [Fact]
    public void GenerateKeyPair_AfterDispose_ShouldThrowObjectDisposedException()
    {
        // Arrange
        _context = KazKemContext.Initialize(SecurityLevel.Level128);
        _context.Dispose();

        // Act & Assert
        Assert.Throws<ObjectDisposedException>(() => _context.GenerateKeyPair());
    }

    [Fact]
    public void Encapsulate_AfterDispose_ShouldThrowObjectDisposedException()
    {
        // Arrange
        _context = KazKemContext.Initialize(SecurityLevel.Level128);
        using var keyPair = _context.GenerateKeyPair();
        var publicKey = keyPair.GetPublicKey();
        _context.Dispose();

        // Act & Assert
        Assert.Throws<ObjectDisposedException>(() => _context.Encapsulate(publicKey));
    }

    [Fact]
    public void Decapsulate_AfterDispose_ShouldThrowObjectDisposedException()
    {
        // Arrange
        _context = KazKemContext.Initialize(SecurityLevel.Level128);
        using var keyPair = _context.GenerateKeyPair();
        using var encResult = _context.Encapsulate(keyPair.GetPublicKey());
        var ciphertext = encResult.ExportCiphertext();
        _context.Dispose();

        // Act & Assert
        Assert.Throws<ObjectDisposedException>(() => _context.Decapsulate(ciphertext, keyPair));
    }

    [Fact]
    public void Encapsulate_WithEmptyPublicKey_ShouldThrowArgumentException()
    {
        // Arrange
        _context = KazKemContext.Initialize(SecurityLevel.Level128);
        var emptyKey = Array.Empty<byte>();

        // Act & Assert
        Assert.Throws<ArgumentException>(() => _context.Encapsulate(emptyKey));
    }

    [Fact]
    public void Decapsulate_WithEmptyPrivateKey_ShouldThrowArgumentException()
    {
        // Arrange
        _context = KazKemContext.Initialize(SecurityLevel.Level128);
        using var keyPair = _context.GenerateKeyPair();
        using var encResult = _context.Encapsulate(keyPair.GetPublicKey());
        var emptyKey = Array.Empty<byte>();

        // Act & Assert
        Assert.Throws<ArgumentException>(() => _context.Decapsulate(encResult.Ciphertext, emptyKey));
    }

    [Fact]
    public void KeyPair_PublicKey_AfterDispose_ShouldThrowObjectDisposedException()
    {
        // Arrange
        _context = KazKemContext.Initialize(SecurityLevel.Level128);
        var keyPair = _context.GenerateKeyPair();
        keyPair.Dispose();

        // Act & Assert
        Assert.Throws<ObjectDisposedException>(() => _ = keyPair.PublicKey);
    }

    [Fact]
    public void KeyPair_PrivateKey_AfterDispose_ShouldThrowObjectDisposedException()
    {
        // Arrange
        _context = KazKemContext.Initialize(SecurityLevel.Level128);
        var keyPair = _context.GenerateKeyPair();
        keyPair.Dispose();

        // Act & Assert
        Assert.Throws<ObjectDisposedException>(() => _ = keyPair.PrivateKey);
    }

    [Fact]
    public void EncapsulationResult_Ciphertext_AfterDispose_ShouldThrowObjectDisposedException()
    {
        // Arrange
        _context = KazKemContext.Initialize(SecurityLevel.Level128);
        using var keyPair = _context.GenerateKeyPair();
        var encResult = _context.Encapsulate(keyPair.GetPublicKey());
        encResult.Dispose();

        // Act & Assert
        Assert.Throws<ObjectDisposedException>(() => _ = encResult.Ciphertext);
    }

    [Fact]
    public void EncapsulationResult_SharedSecret_AfterDispose_ShouldThrowObjectDisposedException()
    {
        // Arrange
        _context = KazKemContext.Initialize(SecurityLevel.Level128);
        using var keyPair = _context.GenerateKeyPair();
        var encResult = _context.Encapsulate(keyPair.GetPublicKey());
        encResult.Dispose();

        // Act & Assert
        Assert.Throws<ObjectDisposedException>(() => _ = encResult.SharedSecret);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(10)]
    [InlineData(53)]  // One less than Level128 public key size
    [InlineData(55)]  // One more than Level128 public key size
    [InlineData(100)]
    public void Encapsulate_WithWrongSizePublicKey_ShouldThrowArgumentException(int keySize)
    {
        // Arrange
        _context = KazKemContext.Initialize(SecurityLevel.Level128);
        var wrongSizeKey = new byte[keySize];

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() => _context.Encapsulate(wrongSizeKey));
        Assert.Contains("Public key", exception.Message);
        Assert.Contains(_context.PublicKeySize.ToString(), exception.Message);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(10)]
    [InlineData(16)]  // One less than Level128 private key size
    [InlineData(18)]  // One more than Level128 private key size
    [InlineData(100)]
    public void Decapsulate_WithWrongSizePrivateKey_ShouldThrowArgumentException(int keySize)
    {
        // Arrange
        _context = KazKemContext.Initialize(SecurityLevel.Level128);
        using var keyPair = _context.GenerateKeyPair();
        using var encResult = _context.Encapsulate(keyPair.GetPublicKey());
        var wrongSizeKey = new byte[keySize];

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            _context.Decapsulate(encResult.Ciphertext, wrongSizeKey));
        Assert.Contains("Private key", exception.Message);
        Assert.Contains(_context.PrivateKeySize.ToString(), exception.Message);
    }

    [Fact]
    public void Encapsulate_NullKazKemPublicKey_ShouldThrowArgumentNullException()
    {
        // Arrange
        _context = KazKemContext.Initialize(SecurityLevel.Level128);

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => _context.Encapsulate((KazKemPublicKey)null!));
    }

    [Fact]
    public void Decapsulate_NullKeyPair_ShouldThrowArgumentNullException()
    {
        // Arrange
        _context = KazKemContext.Initialize(SecurityLevel.Level128);
        using var keyPair = _context.GenerateKeyPair();
        using var encResult = _context.Encapsulate(keyPair.GetPublicKey());

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            _context.Decapsulate(encResult.Ciphertext, (KazKemKeyPair)null!));
    }
}
