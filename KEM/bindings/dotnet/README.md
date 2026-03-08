# KazKem - Post-Quantum Key Encapsulation for .NET

A .NET binding for the KAZ-KEM post-quantum key encapsulation mechanism, providing quantum-resistant key exchange for .NET applications.

## Features

- **Post-Quantum Security**: Resistant to attacks from quantum computers
- **Multiple Security Levels**: 128-bit, 192-bit, and 256-bit options (NIST Levels 1, 3, 5)
- **Cross-Platform**: Windows, Linux, and macOS support
- **Modern .NET**: Targets .NET 8.0 and .NET 9.0
- **Thread-Safe**: Safe for use in multi-threaded applications
- **Secure Memory Handling**: Automatic zeroing of sensitive data

## Installation

### NuGet Package (Coming Soon)

```bash
dotnet add package KazKem
```

### Building from Source

1. Clone the repository
2. Build the native library:

```bash
# Linux/macOS
cd KEM/bindings/dotnet/scripts
./build-native.sh

# Windows (from Developer Command Prompt)
cd KEM\bindings\dotnet\scripts
.\build-native.ps1
```

3. Build the .NET project:

```bash
cd KEM/bindings/dotnet
dotnet build
```

## Quick Start

```csharp
using KazKem;

// Initialize KAZ-KEM with 128-bit security
using var context = KazKemContext.Initialize(SecurityLevel.Level128);

// Generate a key pair
using var keyPair = context.GenerateKeyPair();

// Share the public key with the other party
var publicKey = keyPair.GetPublicKey();

// Other party encapsulates a shared secret
using var encapsulation = context.Encapsulate(publicKey);
byte[] ciphertext = encapsulation.ExportCiphertext();
byte[] senderSecret = encapsulation.ExportSharedSecret();

// Original key holder decapsulates to get the same shared secret
byte[] receiverSecret = context.Decapsulate(ciphertext, keyPair);

// Both parties now have the same shared secret for symmetric encryption
```

## API Reference

### KazKemContext

The main entry point for KAZ-KEM operations.

```csharp
// Initialize with a security level
public static KazKemContext Initialize(SecurityLevel level = SecurityLevel.Level128)

// Get current context (throws if not initialized)
public static KazKemContext Current { get; }

// Check initialization status
public static bool IsInitialized { get; }

// Get library version
public static string Version { get; }

// Key/ciphertext sizes for current security level
public int PublicKeySize { get; }
public int PrivateKeySize { get; }
public int CiphertextSize { get; }
public int SharedSecretSize { get; }

// Generate a new key pair
public KazKemKeyPair GenerateKeyPair()

// Encapsulate a shared secret
public KazKemEncapsulationResult Encapsulate(KazKemPublicKey publicKey)
public KazKemEncapsulationResult Encapsulate(ReadOnlySpan<byte> publicKey)

// Decapsulate a shared secret
public byte[] Decapsulate(ReadOnlySpan<byte> ciphertext, KazKemKeyPair keyPair)
public byte[] Decapsulate(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> privateKey)
```

### SecurityLevel

```csharp
public enum SecurityLevel
{
    Level128 = 128,  // NIST Level 1 - Equivalent to AES-128
    Level192 = 192,  // NIST Level 3 - Equivalent to AES-192
    Level256 = 256   // NIST Level 5 - Equivalent to AES-256
}
```

### KazKemKeyPair

```csharp
// Key data (read-only spans)
public ReadOnlySpan<byte> PublicKey { get; }
public ReadOnlySpan<byte> PrivateKey { get; }

// Export as byte arrays
public byte[] ExportPublicKey()
public byte[] ExportPrivateKey()

// Get shareable public key object
public KazKemPublicKey GetPublicKey()
```

### KazKemEncapsulationResult

```csharp
// Result data (read-only spans)
public ReadOnlySpan<byte> Ciphertext { get; }
public ReadOnlySpan<byte> SharedSecret { get; }

// Export as byte arrays
public byte[] ExportCiphertext()
public byte[] ExportSharedSecret()
```

## Sample Code

### Basic Key Exchange

```csharp
using KazKem;

public class KeyExchangeExample
{
    public static void BasicKeyExchange()
    {
        // Alice initializes and generates her key pair
        using var context = KazKemContext.Initialize(SecurityLevel.Level128);
        using var aliceKeyPair = context.GenerateKeyPair();

        // Alice shares her public key with Bob (e.g., over network)
        byte[] alicePublicKeyBytes = aliceKeyPair.ExportPublicKey();

        // Bob receives Alice's public key and encapsulates a shared secret
        var alicePublicKey = KazKemPublicKey.FromBytes(alicePublicKeyBytes, SecurityLevel.Level128);
        using var encapsulation = context.Encapsulate(alicePublicKey);

        // Bob sends the ciphertext to Alice and keeps the shared secret
        byte[] ciphertext = encapsulation.ExportCiphertext();
        byte[] bobSharedSecret = encapsulation.ExportSharedSecret();

        // Alice decapsulates to get the same shared secret
        byte[] aliceSharedSecret = context.Decapsulate(ciphertext, aliceKeyPair);

        // Both now have identical shared secrets
        Console.WriteLine($"Secrets match: {aliceSharedSecret.SequenceEqual(bobSharedSecret)}");
    }
}
```

### Using with AES Encryption

```csharp
using System.Security.Cryptography;
using KazKem;

public class HybridEncryption
{
    public static (byte[] ciphertext, byte[] kemCiphertext, byte[] nonce) Encrypt(
        byte[] plaintext,
        KazKemPublicKey recipientPublicKey)
    {
        using var context = KazKemContext.Initialize(recipientPublicKey.SecurityLevel);

        // Encapsulate to get shared secret
        using var encapsulation = context.Encapsulate(recipientPublicKey);
        byte[] sharedSecret = encapsulation.ExportSharedSecret();

        // Derive AES key from shared secret using HKDF
        byte[] aesKey = HKDF.DeriveKey(
            HashAlgorithmName.SHA256,
            sharedSecret,
            32,  // 256-bit key
            info: "KAZ-KEM-AES-KEY"u8.ToArray());

        // Encrypt with AES-GCM
        byte[] nonce = new byte[12];
        RandomNumberGenerator.Fill(nonce);

        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[16];

        using var aes = new AesGcm(aesKey, 16);
        aes.Encrypt(nonce, plaintext, ciphertext, tag);

        // Combine ciphertext and tag
        byte[] result = new byte[ciphertext.Length + tag.Length];
        ciphertext.CopyTo(result, 0);
        tag.CopyTo(result, ciphertext.Length);

        // Clean up sensitive data
        CryptographicOperations.ZeroMemory(sharedSecret);
        CryptographicOperations.ZeroMemory(aesKey);

        return (result, encapsulation.ExportCiphertext(), nonce);
    }

    public static byte[] Decrypt(
        byte[] ciphertext,
        byte[] kemCiphertext,
        byte[] nonce,
        KazKemKeyPair recipientKeyPair)
    {
        using var context = KazKemContext.Initialize(recipientKeyPair.SecurityLevel);

        // Decapsulate to get shared secret
        byte[] sharedSecret = context.Decapsulate(kemCiphertext, recipientKeyPair);

        // Derive AES key
        byte[] aesKey = HKDF.DeriveKey(
            HashAlgorithmName.SHA256,
            sharedSecret,
            32,
            info: "KAZ-KEM-AES-KEY"u8.ToArray());

        // Split ciphertext and tag
        byte[] encryptedData = ciphertext[..^16];
        byte[] tag = ciphertext[^16..];

        // Decrypt
        byte[] plaintext = new byte[encryptedData.Length];
        using var aes = new AesGcm(aesKey, 16);
        aes.Decrypt(nonce, encryptedData, tag, plaintext);

        // Clean up
        CryptographicOperations.ZeroMemory(sharedSecret);
        CryptographicOperations.ZeroMemory(aesKey);

        return plaintext;
    }
}
```

### Serialization and Storage

```csharp
using System.Text.Json;
using KazKem;

public class KeySerialization
{
    public record StoredKeyPair(
        string PublicKey,
        string PrivateKey,
        int SecurityLevel);

    public static string SerializeKeyPair(KazKemKeyPair keyPair)
    {
        var stored = new StoredKeyPair(
            Convert.ToBase64String(keyPair.ExportPublicKey()),
            Convert.ToBase64String(keyPair.ExportPrivateKey()),
            (int)keyPair.SecurityLevel);

        return JsonSerializer.Serialize(stored);
    }

    public static (byte[] publicKey, byte[] privateKey, SecurityLevel level) DeserializeKeyPair(string json)
    {
        var stored = JsonSerializer.Deserialize<StoredKeyPair>(json)!;

        return (
            Convert.FromBase64String(stored.PublicKey),
            Convert.FromBase64String(stored.PrivateKey),
            (SecurityLevel)stored.SecurityLevel);
    }
}
```

### ASP.NET Core Integration

```csharp
using KazKem;

public static class KazKemServiceExtensions
{
    public static IServiceCollection AddKazKem(
        this IServiceCollection services,
        SecurityLevel level = SecurityLevel.Level128)
    {
        // Initialize once at startup
        var context = KazKemContext.Initialize(level);

        // Register as singleton
        services.AddSingleton(context);

        return services;
    }
}

// In Program.cs
builder.Services.AddKazKem(SecurityLevel.Level192);

// In a controller or service
public class KeyExchangeService
{
    private readonly KazKemContext _context;

    public KeyExchangeService(KazKemContext context)
    {
        _context = context;
    }

    public (byte[] publicKey, byte[] privateKey) GenerateKeyPair()
    {
        using var keyPair = _context.GenerateKeyPair();
        return (keyPair.ExportPublicKey(), keyPair.ExportPrivateKey());
    }
}
```

## Best Practices

### 1. Always Dispose Key Material

Key pairs and encapsulation results contain sensitive cryptographic material. Always use `using` statements or explicitly call `Dispose()`:

```csharp
// Good - automatic disposal
using var keyPair = context.GenerateKeyPair();
using var result = context.Encapsulate(publicKey);

// Also good - explicit disposal
var keyPair = context.GenerateKeyPair();
try
{
    // Use key pair
}
finally
{
    keyPair.Dispose();
}
```

### 2. Zero Sensitive Data After Use

When you export keys or secrets to byte arrays, zero them when done:

```csharp
byte[] sharedSecret = context.Decapsulate(ciphertext, keyPair);
try
{
    // Use the shared secret
    DeriveKeys(sharedSecret);
}
finally
{
    CryptographicOperations.ZeroMemory(sharedSecret);
}
```

### 3. Choose Appropriate Security Level

| Level | Security | Performance | Use Case |
|-------|----------|-------------|----------|
| 128 | Good | Fastest | General purpose, most applications |
| 192 | Better | Medium | Higher security requirements |
| 256 | Best | Slowest | Maximum security, long-term secrets |

```csharp
// For most applications
var context = KazKemContext.Initialize(SecurityLevel.Level128);

// For high-security applications
var context = KazKemContext.Initialize(SecurityLevel.Level256);
```

### 4. Initialize Once, Reuse Context

The context should be initialized once and reused throughout the application lifecycle:

```csharp
// Good - singleton pattern
public class CryptoService
{
    private static readonly Lazy<KazKemContext> _context =
        new(() => KazKemContext.Initialize(SecurityLevel.Level128));

    public static KazKemContext Context => _context.Value;
}

// Bad - creating new context for each operation
public void BadExample()
{
    using var context = KazKemContext.Initialize(); // Wasteful
    // ...
}
```

### 5. Handle Exceptions Appropriately

```csharp
try
{
    using var context = KazKemContext.Initialize(SecurityLevel.Level128);
    using var keyPair = context.GenerateKeyPair();
    // ...
}
catch (KazKemNotInitializedException ex)
{
    // Library not properly initialized
    logger.LogError(ex, "KAZ-KEM initialization failed");
}
catch (KazKemException ex)
{
    // General cryptographic error
    logger.LogError(ex, "KAZ-KEM operation failed: {ErrorCode}", ex.ErrorCode);
}
```

### 6. Never Store Private Keys in Plain Text

Always encrypt private keys before storage:

```csharp
public static byte[] ProtectPrivateKey(byte[] privateKey, byte[] password)
{
    // Use DPAPI on Windows or similar on other platforms
    return ProtectedData.Protect(
        privateKey,
        password,
        DataProtectionScope.CurrentUser);
}
```

### 7. Use Hybrid Encryption

KEM produces a shared secret, not encrypted data. Always combine with symmetric encryption:

```csharp
// KEM for key exchange + AES for data encryption
var (kemCiphertext, sharedSecret) = Encapsulate(publicKey);
var encryptedData = AesGcmEncrypt(data, DeriveKey(sharedSecret));
```

### 8. Validate Input Sizes

The library validates input sizes, but you can check proactively:

```csharp
public void ValidatePublicKey(byte[] publicKey, KazKemContext context)
{
    if (publicKey.Length != context.PublicKeySize)
    {
        throw new ArgumentException(
            $"Invalid public key size. Expected {context.PublicKeySize}, got {publicKey.Length}");
    }
}
```

## Platform Support

| Platform | Architecture | Status |
|----------|-------------|--------|
| Windows | x64 | Supported |
| Windows | ARM64 | Supported |
| Linux | x64 | Supported |
| Linux | ARM64 | Supported |
| macOS | x64 | Supported |
| macOS | ARM64 | Supported |

## Dependencies

- .NET 8.0 or .NET 9.0
- OpenSSL 3.x (for native library)

## Building Native Libraries

### Prerequisites

- C compiler (GCC, Clang, or MSVC)
- OpenSSL development headers

### Linux

```bash
sudo apt-get install libssl-dev  # Debian/Ubuntu
sudo yum install openssl-devel   # RHEL/CentOS

./scripts/build-native.sh
```

### macOS

```bash
brew install openssl@3

./scripts/build-native.sh
```

### Windows

```powershell
# Install OpenSSL (e.g., via winget or manual download)
# Run from Developer Command Prompt

.\scripts\build-native.ps1 -OpenSSLPath "C:\OpenSSL-Win64"
```

## License

This project is licensed under the NIST Software License. See the LICENSE file for details.

## Security Considerations

- This is a post-quantum cryptographic implementation
- The underlying algorithm provides security against both classical and quantum attacks
- Always use the latest version for security updates
- Consider security audits for production deployments

## Contributing

Contributions are welcome! Please see the main repository for contribution guidelines.

## Support

For issues and questions:
- GitHub Issues: https://github.com/pqc-kaz/pqc-kaz/issues
