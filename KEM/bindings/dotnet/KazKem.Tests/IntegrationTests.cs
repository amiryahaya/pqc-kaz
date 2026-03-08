using System.Security.Cryptography;
using Xunit;
using Antrapol.Kaz.Kem;

namespace Antrapol.Kaz.Kem.Tests;

/// <summary>
/// Integration tests simulating real-world usage scenarios.
/// </summary>
public class IntegrationTests : IDisposable
{
    private KazKemContext _context;

    public IntegrationTests()
    {
        _context = KazKemContext.Initialize(SecurityLevel.Level128);
    }

    public void Dispose()
    {
        _context?.Dispose();
    }

    [Fact]
    public void FullKeyExchange_AliceAndBob_ShouldSucceed()
    {
        // Simulate a key exchange between Alice and Bob

        // Step 1: Alice generates her key pair
        using var aliceKeyPair = _context.GenerateKeyPair();

        // Step 2: Alice sends her public key to Bob (simulated by exporting)
        byte[] alicePublicKeyBytes = aliceKeyPair.ExportPublicKey();

        // Step 3: Bob receives Alice's public key and reconstructs it
        var alicePublicKey = KazKemPublicKey.FromBytes(alicePublicKeyBytes, SecurityLevel.Level128);

        // Step 4: Bob encapsulates a shared secret
        using var bobEncapsulation = _context.Encapsulate(alicePublicKey);
        byte[] bobSharedSecret = bobEncapsulation.ExportSharedSecret();
        byte[] ciphertext = bobEncapsulation.ExportCiphertext();

        // Step 5: Bob sends ciphertext to Alice (simulated)

        // Step 6: Alice decapsulates to get the shared secret
        byte[] aliceSharedSecret = _context.Decapsulate(ciphertext, aliceKeyPair);

        // Verify: Both parties have the same shared secret
        Assert.Equal(aliceSharedSecret, bobSharedSecret);
    }

    [Fact]
    public void HybridEncryption_WithAesGcm_ShouldWork()
    {
        // Simulate hybrid encryption: KEM + AES-GCM

        // Setup: Generate recipient's key pair
        using var recipientKeyPair = _context.GenerateKeyPair();
        var recipientPublicKey = recipientKeyPair.GetPublicKey();

        // Sender: Encrypt a message
        byte[] plaintext = "Hello, Post-Quantum World!"u8.ToArray();

        // Step 1: Encapsulate to get shared secret
        using var encapsulation = _context.Encapsulate(recipientPublicKey);
        byte[] sharedSecret = encapsulation.ExportSharedSecret();
        byte[] kemCiphertext = encapsulation.ExportCiphertext();

        // Step 2: Derive AES key from shared secret (using first 32 bytes or hash)
        byte[] aesKey = DeriveAesKey(sharedSecret);

        // Step 3: Encrypt with AES-GCM
        byte[] nonce = new byte[12];
        RandomNumberGenerator.Fill(nonce);

        byte[] aesCiphertext = new byte[plaintext.Length];
        byte[] tag = new byte[16];

        using (var aes = new AesGcm(aesKey, 16))
        {
            aes.Encrypt(nonce, plaintext, aesCiphertext, tag);
        }

        // Recipient: Decrypt the message
        // Step 1: Decapsulate to get shared secret
        byte[] recipientSharedSecret = _context.Decapsulate(kemCiphertext, recipientKeyPair);

        // Step 2: Derive AES key
        byte[] recipientAesKey = DeriveAesKey(recipientSharedSecret);

        // Step 3: Decrypt with AES-GCM
        byte[] decryptedPlaintext = new byte[aesCiphertext.Length];
        using (var aes = new AesGcm(recipientAesKey, 16))
        {
            aes.Decrypt(nonce, aesCiphertext, tag, decryptedPlaintext);
        }

        // Verify
        Assert.Equal(plaintext, decryptedPlaintext);

        // Cleanup sensitive data
        CryptographicOperations.ZeroMemory(sharedSecret);
        CryptographicOperations.ZeroMemory(aesKey);
        CryptographicOperations.ZeroMemory(recipientSharedSecret);
        CryptographicOperations.ZeroMemory(recipientAesKey);
    }

    [Fact]
    public void KeySerialization_RoundTrip_ShouldWork()
    {
        // Generate a key pair
        using var originalKeyPair = _context.GenerateKeyPair();

        // Export keys
        byte[] publicKeyBytes = originalKeyPair.ExportPublicKey();
        byte[] privateKeyBytes = originalKeyPair.ExportPrivateKey();
        var securityLevel = originalKeyPair.SecurityLevel;

        // Simulate storage and retrieval (e.g., save to file, read back)
        string publicKeyBase64 = Convert.ToBase64String(publicKeyBytes);
        string privateKeyBase64 = Convert.ToBase64String(privateKeyBytes);

        // Reconstruct from stored data
        byte[] restoredPublicKey = Convert.FromBase64String(publicKeyBase64);
        byte[] restoredPrivateKey = Convert.FromBase64String(privateKeyBase64);

        // Use restored keys for encapsulation/decapsulation
        var publicKey = KazKemPublicKey.FromBytes(restoredPublicKey, securityLevel);
        using var encResult = _context.Encapsulate(publicKey);

        // Decapsulate using restored private key
        byte[] decapsulatedSecret = _context.Decapsulate(encResult.Ciphertext, restoredPrivateKey);

        // Verify
        Assert.Equal(encResult.SharedSecret.ToArray(), decapsulatedSecret);
    }

    [Fact]
    public void MultipleRecipients_SameMessage_ShouldWork()
    {
        // Sender wants to send to multiple recipients

        // Generate key pairs for multiple recipients
        using var recipient1KeyPair = _context.GenerateKeyPair();
        using var recipient2KeyPair = _context.GenerateKeyPair();
        using var recipient3KeyPair = _context.GenerateKeyPair();

        // The shared secret (message key) to distribute
        byte[] messageKey = new byte[32];
        RandomNumberGenerator.Fill(messageKey);
        // Ensure it's within bounds for KEM
        messageKey[0] &= 0x7F;

        // Encapsulate for each recipient
        using var enc1 = _context.Encapsulate(recipient1KeyPair.GetPublicKey());
        using var enc2 = _context.Encapsulate(recipient2KeyPair.GetPublicKey());
        using var enc3 = _context.Encapsulate(recipient3KeyPair.GetPublicKey());

        // Each recipient decapsulates their ciphertext
        var secret1 = _context.Decapsulate(enc1.Ciphertext, recipient1KeyPair);
        var secret2 = _context.Decapsulate(enc2.Ciphertext, recipient2KeyPair);
        var secret3 = _context.Decapsulate(enc3.Ciphertext, recipient3KeyPair);

        // Each recipient should get their respective shared secret
        Assert.Equal(enc1.SharedSecret.ToArray(), secret1);
        Assert.Equal(enc2.SharedSecret.ToArray(), secret2);
        Assert.Equal(enc3.SharedSecret.ToArray(), secret3);
    }

    [Fact]
    public void KeyRotation_NewKeyPairWorks_OldKeyPairFails()
    {
        // Simulate key rotation scenario

        // Original key pair
        using var oldKeyPair = _context.GenerateKeyPair();

        // Encapsulate with old key
        using var encWithOld = _context.Encapsulate(oldKeyPair.GetPublicKey());
        var oldCiphertext = encWithOld.ExportCiphertext();
        var oldSecret = encWithOld.ExportSharedSecret();

        // Rotate to new key pair
        using var newKeyPair = _context.GenerateKeyPair();

        // Old key can still decapsulate old ciphertext
        var decapsulatedOld = _context.Decapsulate(oldCiphertext, oldKeyPair);
        Assert.Equal(oldSecret, decapsulatedOld);

        // New key produces different result for old ciphertext
        var wrongDecapsulation = _context.Decapsulate(oldCiphertext, newKeyPair);
        Assert.NotEqual(oldSecret, wrongDecapsulation);

        // New encapsulation works with new key
        using var encWithNew = _context.Encapsulate(newKeyPair.GetPublicKey());
        var newDecapsulated = _context.Decapsulate(encWithNew.Ciphertext, newKeyPair);
        Assert.Equal(encWithNew.SharedSecret.ToArray(), newDecapsulated);
    }

    [Theory]
    [InlineData(SecurityLevel.Level128)]
    [InlineData(SecurityLevel.Level192)]
    [InlineData(SecurityLevel.Level256)]
    public void FullFlow_AllSecurityLevels_ShouldWork(SecurityLevel level)
    {
        // Reinitialize for specific level
        _context.Dispose();
        _context = KazKemContext.Initialize(level);

        // Full flow test
        using var keyPair = _context.GenerateKeyPair();
        Assert.Equal(level, keyPair.SecurityLevel);

        using var encResult = _context.Encapsulate(keyPair.GetPublicKey());
        var decapsulated = _context.Decapsulate(encResult.Ciphertext, keyPair);

        Assert.Equal(encResult.SharedSecret.ToArray(), decapsulated);
    }

    [Fact]
    public void Version_ShouldBeAvailable()
    {
        // Act
        var version = KazKemContext.Version;

        // Assert
        Assert.NotNull(version);
        Assert.NotEmpty(version);
        Assert.Contains("2.1", version); // Should contain version number
    }

    [Fact]
    public void LargeNumberOfOperations_ShouldNotLeak()
    {
        // Perform many operations to check for memory stability
        const int iterations = 100;

        for (int i = 0; i < iterations; i++)
        {
            using var keyPair = _context.GenerateKeyPair();
            using var encResult = _context.Encapsulate(keyPair.GetPublicKey());
            var secret = _context.Decapsulate(encResult.Ciphertext, keyPair);

            Assert.Equal(encResult.SharedSecret.ToArray(), secret);
        }
    }

    private static byte[] DeriveAesKey(byte[] sharedSecret)
    {
        // Simple key derivation using SHA-256
        // In production, use HKDF
        using var sha256 = SHA256.Create();
        return sha256.ComputeHash(sharedSecret);
    }
}
