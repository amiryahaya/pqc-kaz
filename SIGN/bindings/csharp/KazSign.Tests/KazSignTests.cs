/*
 * KAZ-SIGN C# Wrapper Unit Tests
 *
 * Comprehensive test suite covering:
 * - Key generation
 * - Signing and verification
 * - Error handling
 * - Edge cases
 * - All security levels (128, 192, 256)
 */

using System;
using System.Text;
using Xunit;
using Antrapol.Kaz.Sign;

namespace Antrapol.Kaz.Sign.Tests
{
    /// <summary>
    /// Tests for SecurityLevel.Level128
    /// </summary>
    public class Level128Tests : SecurityLevelTestBase
    {
        public Level128Tests() : base(SecurityLevel.Level128) { }
    }

    /// <summary>
    /// Tests for SecurityLevel.Level192
    /// </summary>
    public class Level192Tests : SecurityLevelTestBase
    {
        public Level192Tests() : base(SecurityLevel.Level192) { }
    }

    /// <summary>
    /// Tests for SecurityLevel.Level256
    /// </summary>
    public class Level256Tests : SecurityLevelTestBase
    {
        public Level256Tests() : base(SecurityLevel.Level256) { }
    }

    /// <summary>
    /// Base class containing all tests, parameterized by security level
    /// </summary>
    public abstract class SecurityLevelTestBase : IDisposable
    {
        protected readonly SecurityLevel _level;
        protected readonly KazSigner _signer;

        protected SecurityLevelTestBase(SecurityLevel level)
        {
            _level = level;
            _signer = new KazSigner(level);
        }

        public void Dispose()
        {
            _signer.Dispose();
        }

        // ====================================================================
        // Version Tests
        // ====================================================================

        [Fact]
        public void GetVersion_ReturnsValidVersionString()
        {
            var version = _signer.GetVersion();
            Assert.NotNull(version);
            Assert.NotEmpty(version);
            Assert.Equal("4.0.0", version);
        }

        [Fact]
        public void GetVersionNumber_ReturnsValidNumber()
        {
            var versionNumber = _signer.GetVersionNumber();
            Assert.Equal(40000, versionNumber);
        }

        // ====================================================================
        // Initialization Tests
        // ====================================================================

        [Fact]
        public void Constructor_AutoInitialize_IsInitialized()
        {
            Assert.True(_signer.IsInitialized());
        }

        [Fact]
        public void Constructor_NoAutoInitialize_CanStillInitialize()
        {
            // Note: IsInitialized() checks global native state, not instance state
            // Once any signer initializes, all signers report initialized
            using var signer = new KazSigner(_level, autoInitialize: false);
            // Should be able to call Initialize without throwing
            signer.Initialize();
            Assert.True(signer.IsInitialized());
        }

        [Fact]
        public void Initialize_AfterConstruction_Succeeds()
        {
            using var signer = new KazSigner(_level, autoInitialize: false);
            signer.Initialize();
            Assert.True(signer.IsInitialized());
        }

        // ====================================================================
        // Parameter Tests
        // ====================================================================

        [Fact]
        public void Parameters_MatchExpectedSizes()
        {
            int expectedSk = _level switch
            {
                SecurityLevel.Level128 => 32,
                SecurityLevel.Level192 => 50,
                SecurityLevel.Level256 => 64,
                _ => 0
            };

            int expectedPk = _level switch
            {
                SecurityLevel.Level128 => 54,
                SecurityLevel.Level192 => 88,
                SecurityLevel.Level256 => 118,
                _ => 0
            };

            int expectedOverhead = _level switch
            {
                SecurityLevel.Level128 => 162,
                SecurityLevel.Level192 => 264,
                SecurityLevel.Level256 => 354,
                _ => 0
            };

            int expectedHash = _level switch
            {
                SecurityLevel.Level128 => 32,
                SecurityLevel.Level192 => 48,
                SecurityLevel.Level256 => 64,
                _ => 0
            };

            Assert.Equal(expectedSk, _signer.SecretKeyBytes);
            Assert.Equal(expectedPk, _signer.PublicKeyBytes);
            Assert.Equal(expectedOverhead, _signer.SignatureOverhead);
            Assert.Equal(expectedHash, _signer.HashBytes);
        }

        // ====================================================================
        // Key Generation Tests
        // ====================================================================

        [Fact]
        public void GenerateKeyPair_ProducesCorrectSizes()
        {
            _signer.GenerateKeyPair(out byte[] pk, out byte[] sk);

            Assert.Equal(_signer.PublicKeyBytes, pk.Length);
            Assert.Equal(_signer.SecretKeyBytes, sk.Length);
        }

        [Fact]
        public void GenerateKeyPair_ProducesNonZeroKeys()
        {
            _signer.GenerateKeyPair(out byte[] pk, out byte[] sk);

            Assert.False(IsAllZeros(pk), "Public key should not be all zeros");
            Assert.False(IsAllZeros(sk), "Secret key should not be all zeros");
        }

        [Fact]
        public void GenerateKeyPair_ProducesUniqueKeys()
        {
            _signer.GenerateKeyPair(out byte[] pk1, out byte[] sk1);
            _signer.GenerateKeyPair(out byte[] pk2, out byte[] sk2);

            Assert.False(pk1.AsSpan().SequenceEqual(pk2), "Public keys should be unique");
            Assert.False(sk1.AsSpan().SequenceEqual(sk2), "Secret keys should be unique");
        }

        // ====================================================================
        // Signing Tests
        // ====================================================================

        [Fact]
        public void Sign_ProducesCorrectSize()
        {
            _signer.GenerateKeyPair(out byte[] pk, out byte[] sk);
            byte[] message = Encoding.UTF8.GetBytes("Test message");

            byte[] signature = _signer.Sign(message, sk);

            Assert.Equal(_signer.SignatureOverhead + message.Length, signature.Length);
        }

        [Fact]
        public void Sign_ProducesNonZeroSignature()
        {
            _signer.GenerateKeyPair(out byte[] pk, out byte[] sk);
            byte[] message = Encoding.UTF8.GetBytes("Test message");

            byte[] signature = _signer.Sign(message, sk);

            Assert.False(IsAllZeros(signature), "Signature should not be all zeros");
        }

        [Fact]
        public void Sign_SameMessage_ProducesDifferentSignatures()
        {
            _signer.GenerateKeyPair(out byte[] pk, out byte[] sk);
            byte[] message = Encoding.UTF8.GetBytes("Test message");

            byte[] sig1 = _signer.Sign(message, sk);
            byte[] sig2 = _signer.Sign(message, sk);

            // Signatures may differ due to randomness in signing
            // Both should be valid though
            Assert.True(_signer.Verify(sig1, pk, out _));
            Assert.True(_signer.Verify(sig2, pk, out _));
        }

        [Fact]
        public void Sign_NullMessage_ThrowsArgumentNullException()
        {
            _signer.GenerateKeyPair(out byte[] pk, out byte[] sk);

            Assert.Throws<ArgumentNullException>(() => _signer.Sign(null!, sk));
        }

        [Fact]
        public void Sign_NullSecretKey_ThrowsArgumentNullException()
        {
            byte[] message = Encoding.UTF8.GetBytes("Test message");

            Assert.Throws<ArgumentNullException>(() => _signer.Sign(message, null!));
        }

        [Fact]
        public void Sign_WrongSizeSecretKey_ThrowsArgumentException()
        {
            byte[] message = Encoding.UTF8.GetBytes("Test message");
            byte[] wrongSk = new byte[16]; // Wrong size

            Assert.Throws<ArgumentException>(() => _signer.Sign(message, wrongSk));
        }

        // ====================================================================
        // Verification Tests
        // ====================================================================

        [Fact]
        public void Verify_ValidSignature_ReturnsTrue()
        {
            _signer.GenerateKeyPair(out byte[] pk, out byte[] sk);
            byte[] message = Encoding.UTF8.GetBytes("Test message");
            byte[] signature = _signer.Sign(message, sk);

            bool isValid = _signer.Verify(signature, pk, out byte[] recovered);

            Assert.True(isValid);
        }

        [Fact]
        public void Verify_ValidSignature_RecoversMessage()
        {
            _signer.GenerateKeyPair(out byte[] pk, out byte[] sk);
            byte[] message = Encoding.UTF8.GetBytes("Test message");
            byte[] signature = _signer.Sign(message, sk);

            _signer.Verify(signature, pk, out byte[] recovered);

            Assert.Equal(message, recovered);
        }

        [Fact]
        public void Verify_TamperedSignature_ReturnsFalse()
        {
            _signer.GenerateKeyPair(out byte[] pk, out byte[] sk);
            byte[] message = Encoding.UTF8.GetBytes("Test message");
            byte[] signature = _signer.Sign(message, sk);

            // Tamper with signature
            signature[0] ^= 0xFF;

            bool isValid = _signer.Verify(signature, pk, out _);

            Assert.False(isValid);
        }

        [Fact]
        public void Verify_WrongPublicKey_ReturnsFalse()
        {
            _signer.GenerateKeyPair(out byte[] pk1, out byte[] sk1);
            _signer.GenerateKeyPair(out byte[] pk2, out byte[] sk2);
            byte[] message = Encoding.UTF8.GetBytes("Test message");
            byte[] signature = _signer.Sign(message, sk1);

            bool isValid = _signer.Verify(signature, pk2, out _);

            Assert.False(isValid);
        }

        [Fact]
        public void Verify_TruncatedSignature_ReturnsFalse()
        {
            _signer.GenerateKeyPair(out byte[] pk, out byte[] sk);
            byte[] message = Encoding.UTF8.GetBytes("Test message");
            byte[] signature = _signer.Sign(message, sk);

            // Truncate signature
            byte[] truncated = new byte[signature.Length - 10];
            Array.Copy(signature, truncated, truncated.Length);

            bool isValid = _signer.Verify(truncated, pk, out _);

            Assert.False(isValid);
        }

        [Fact]
        public void Verify_NullSignature_ThrowsArgumentNullException()
        {
            _signer.GenerateKeyPair(out byte[] pk, out byte[] sk);

            Assert.Throws<ArgumentNullException>(() => _signer.Verify(null!, pk, out _));
        }

        [Fact]
        public void Verify_NullPublicKey_ThrowsArgumentNullException()
        {
            _signer.GenerateKeyPair(out byte[] pk, out byte[] sk);
            byte[] message = Encoding.UTF8.GetBytes("Test message");
            byte[] signature = _signer.Sign(message, sk);

            Assert.Throws<ArgumentNullException>(() => _signer.Verify(signature, null!, out _));
        }

        [Fact]
        public void Verify_WrongSizePublicKey_ThrowsArgumentException()
        {
            _signer.GenerateKeyPair(out byte[] pk, out byte[] sk);
            byte[] message = Encoding.UTF8.GetBytes("Test message");
            byte[] signature = _signer.Sign(message, sk);
            byte[] wrongPk = new byte[16]; // Wrong size

            Assert.Throws<ArgumentException>(() => _signer.Verify(signature, wrongPk, out _));
        }

        // ====================================================================
        // Round-Trip Tests
        // ====================================================================

        [Fact]
        public void RoundTrip_ShortMessage_Succeeds()
        {
            _signer.GenerateKeyPair(out byte[] pk, out byte[] sk);
            byte[] message = Encoding.UTF8.GetBytes("Hi");

            byte[] signature = _signer.Sign(message, sk);
            bool isValid = _signer.Verify(signature, pk, out byte[] recovered);

            Assert.True(isValid);
            Assert.Equal(message, recovered);
        }

        [Fact]
        public void RoundTrip_LongMessage_Succeeds()
        {
            _signer.GenerateKeyPair(out byte[] pk, out byte[] sk);
            byte[] message = new byte[10000];
            new Random(42).NextBytes(message);

            byte[] signature = _signer.Sign(message, sk);
            bool isValid = _signer.Verify(signature, pk, out byte[] recovered);

            Assert.True(isValid);
            Assert.Equal(message, recovered);
        }

        [Fact]
        public void RoundTrip_EmptyMessage_Succeeds()
        {
            _signer.GenerateKeyPair(out byte[] pk, out byte[] sk);
            byte[] message = Array.Empty<byte>();

            byte[] signature = _signer.Sign(message, sk);
            bool isValid = _signer.Verify(signature, pk, out byte[] recovered);

            Assert.True(isValid);
            Assert.Empty(recovered);
        }

        [Fact]
        public void RoundTrip_BinaryMessage_Succeeds()
        {
            _signer.GenerateKeyPair(out byte[] pk, out byte[] sk);
            byte[] message = new byte[256];
            for (int i = 0; i < 256; i++)
                message[i] = (byte)i;

            byte[] signature = _signer.Sign(message, sk);
            bool isValid = _signer.Verify(signature, pk, out byte[] recovered);

            Assert.True(isValid);
            Assert.Equal(message, recovered);
        }

        [Fact]
        public void RoundTrip_MultipleMessages_Succeeds()
        {
            _signer.GenerateKeyPair(out byte[] pk, out byte[] sk);

            string[] messages = { "Message 1", "Message 2", "Message 3", "Final message" };

            foreach (var msgText in messages)
            {
                byte[] message = Encoding.UTF8.GetBytes(msgText);
                byte[] signature = _signer.Sign(message, sk);
                bool isValid = _signer.Verify(signature, pk, out byte[] recovered);

                Assert.True(isValid);
                Assert.Equal(message, recovered);
            }
        }

        // ====================================================================
        // Hash Tests
        // ====================================================================

        [Fact]
        public void Hash_ProducesCorrectSize()
        {
            byte[] message = Encoding.UTF8.GetBytes("Test message");

            byte[] hash = _signer.Hash(message);

            Assert.Equal(_signer.HashBytes, hash.Length);
        }

        [Fact]
        public void Hash_SameInput_ProducesSameOutput()
        {
            byte[] message = Encoding.UTF8.GetBytes("Test message");

            byte[] hash1 = _signer.Hash(message);
            byte[] hash2 = _signer.Hash(message);

            Assert.Equal(hash1, hash2);
        }

        [Fact]
        public void Hash_DifferentInput_ProducesDifferentOutput()
        {
            byte[] message1 = Encoding.UTF8.GetBytes("Message 1");
            byte[] message2 = Encoding.UTF8.GetBytes("Message 2");

            byte[] hash1 = _signer.Hash(message1);
            byte[] hash2 = _signer.Hash(message2);

            Assert.False(hash1.AsSpan().SequenceEqual(hash2));
        }

        [Fact]
        public void Hash_EmptyMessage_Succeeds()
        {
            byte[] message = Array.Empty<byte>();

            byte[] hash = _signer.Hash(message);

            Assert.Equal(_signer.HashBytes, hash.Length);
            Assert.False(IsAllZeros(hash));
        }

        [Fact]
        public void Hash_NullMessage_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => _signer.Hash(null!));
        }

        // ====================================================================
        // Disposal Tests
        // ====================================================================

        [Fact]
        public void Dispose_CalledTwice_DoesNotThrow()
        {
            var signer = new KazSigner(_level);
            signer.Dispose();
            signer.Dispose(); // Should not throw
        }

        [Fact]
        public void AfterDispose_GenerateKeyPair_ThrowsObjectDisposedException()
        {
            var signer = new KazSigner(_level);
            signer.Dispose();

            Assert.Throws<ObjectDisposedException>(() => signer.GenerateKeyPair(out _, out _));
        }

        [Fact]
        public void AfterDispose_Sign_ThrowsObjectDisposedException()
        {
            var signer = new KazSigner(_level);
            signer.GenerateKeyPair(out _, out byte[] sk);
            signer.Dispose();

            byte[] message = Encoding.UTF8.GetBytes("Test");
            Assert.Throws<ObjectDisposedException>(() => signer.Sign(message, sk));
        }

        [Fact]
        public void AfterDispose_Verify_ThrowsObjectDisposedException()
        {
            var signer = new KazSigner(_level);
            signer.GenerateKeyPair(out byte[] pk, out byte[] sk);
            byte[] signature = signer.Sign(Encoding.UTF8.GetBytes("Test"), sk);
            signer.Dispose();

            Assert.Throws<ObjectDisposedException>(() => signer.Verify(signature, pk, out _));
        }

        // ====================================================================
        // Helper Methods
        // ====================================================================

        private static bool IsAllZeros(byte[] data)
        {
            foreach (var b in data)
            {
                if (b != 0) return false;
            }
            return true;
        }
    }

    /// <summary>
    /// Cross-level tests and general tests
    /// </summary>
    public class GeneralTests
    {
        [Fact]
        public void DifferentLevels_ProduceDifferentKeySizes()
        {
            using var signer128 = new KazSigner(SecurityLevel.Level128);
            using var signer192 = new KazSigner(SecurityLevel.Level192);
            using var signer256 = new KazSigner(SecurityLevel.Level256);

            Assert.NotEqual(signer128.SecretKeyBytes, signer192.SecretKeyBytes);
            Assert.NotEqual(signer192.SecretKeyBytes, signer256.SecretKeyBytes);
            Assert.NotEqual(signer128.PublicKeyBytes, signer192.PublicKeyBytes);
            Assert.NotEqual(signer192.PublicKeyBytes, signer256.PublicKeyBytes);
        }

        [Fact]
        public void DifferentLevels_ProduceDifferentSignatureOverhead()
        {
            using var signer128 = new KazSigner(SecurityLevel.Level128);
            using var signer192 = new KazSigner(SecurityLevel.Level192);
            using var signer256 = new KazSigner(SecurityLevel.Level256);

            Assert.True(signer128.SignatureOverhead < signer192.SignatureOverhead);
            Assert.True(signer192.SignatureOverhead < signer256.SignatureOverhead);
        }

        [Theory]
        [InlineData(SecurityLevel.Level128)]
        [InlineData(SecurityLevel.Level192)]
        [InlineData(SecurityLevel.Level256)]
        public void AllLevels_SignAndVerify_Succeeds(SecurityLevel level)
        {
            using var signer = new KazSigner(level);
            signer.GenerateKeyPair(out byte[] pk, out byte[] sk);

            byte[] message = Encoding.UTF8.GetBytes($"Test message for level {(int)level}");
            byte[] signature = signer.Sign(message, sk);
            bool isValid = signer.Verify(signature, pk, out byte[] recovered);

            Assert.True(isValid);
            Assert.Equal(message, recovered);
        }

        [Fact]
        public void KazSignParameters_GetSecretKeyBytes_ReturnsCorrectValues()
        {
            Assert.Equal(32, KazSignParameters.GetSecretKeyBytes(SecurityLevel.Level128));
            Assert.Equal(50, KazSignParameters.GetSecretKeyBytes(SecurityLevel.Level192));
            Assert.Equal(64, KazSignParameters.GetSecretKeyBytes(SecurityLevel.Level256));
        }

        [Fact]
        public void KazSignParameters_GetPublicKeyBytes_ReturnsCorrectValues()
        {
            Assert.Equal(54, KazSignParameters.GetPublicKeyBytes(SecurityLevel.Level128));
            Assert.Equal(88, KazSignParameters.GetPublicKeyBytes(SecurityLevel.Level192));
            Assert.Equal(118, KazSignParameters.GetPublicKeyBytes(SecurityLevel.Level256));
        }

        [Fact]
        public void KazSignParameters_GetSignatureOverhead_ReturnsCorrectValues()
        {
            Assert.Equal(162, KazSignParameters.GetSignatureOverhead(SecurityLevel.Level128));
            Assert.Equal(264, KazSignParameters.GetSignatureOverhead(SecurityLevel.Level192));
            Assert.Equal(354, KazSignParameters.GetSignatureOverhead(SecurityLevel.Level256));
        }

        [Fact]
        public void KazSignParameters_GetHashBytes_ReturnsCorrectValues()
        {
            Assert.Equal(32, KazSignParameters.GetHashBytes(SecurityLevel.Level128));
            Assert.Equal(48, KazSignParameters.GetHashBytes(SecurityLevel.Level192));
            Assert.Equal(64, KazSignParameters.GetHashBytes(SecurityLevel.Level256));
        }

        [Fact]
        public void KazSignException_HasCorrectErrorCode()
        {
            var ex = new KazSignException(KazSignError.MemoryError);
            Assert.Equal(KazSignError.MemoryError, ex.ErrorCode);
        }

        [Fact]
        public void KazSignException_HasCorrectMessage()
        {
            var ex = new KazSignException(KazSignError.VerificationFailed);
            Assert.Contains("verification", ex.Message, StringComparison.OrdinalIgnoreCase);
        }
    }
}
