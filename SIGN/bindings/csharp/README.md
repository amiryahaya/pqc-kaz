# KAZ-SIGN C# Bindings

C# wrapper for the KAZ-SIGN post-quantum digital signature library.

## Requirements

- .NET 10.0 (default) or .NET 9.0
- Native KAZ-SIGN shared library (built from the C source)

## Building the Native Library

First, build the native shared library for your platform:

```bash
# Navigate to the main project directory
cd /path/to/combined

# Build shared libraries for all security levels
make shared-all

# Or build for a specific level
make shared LEVEL=128
make shared LEVEL=192
make shared LEVEL=256
```

This creates:
- macOS: `build/lib/libkazsign_128.dylib`, `libkazsign_192.dylib`, `libkazsign_256.dylib`
- Linux: `build/lib/libkazsign_128.so`, `libkazsign_192.so`, `libkazsign_256.so`
- Windows: `build/lib/kazsign_128.dll`, `kazsign_192.dll`, `kazsign_256.dll`

## Building the C# Project

```bash
cd bindings/csharp/Example
dotnet build
```

## Running the Example

```bash
dotnet run
```

## Running Tests

```bash
cd KazSign.Tests

# Build and copy native libraries
dotnet build
cp ../../../build/lib/*.dylib bin/Debug/net10.0/   # macOS
# cp ../../../build/lib/*.so bin/Debug/net10.0/    # Linux

# Run all tests (122 tests across all security levels)
dotnet test
```

Test coverage includes:
- Key generation (correct sizes, uniqueness, non-zero)
- Signing (correct sizes, null checks, wrong key sizes)
- Verification (valid signatures, tampered, wrong keys, truncated)
- Round-trip (short/long/empty/binary messages)
- Hash function (determinism, correct sizes)
- Error handling (null arguments, disposed objects)
- All security levels (128, 192, 256)

## Usage

```csharp
using KazSign;

// Create a signer with desired security level
using var signer = new KazSigner(SecurityLevel.Level128);

// Generate a key pair
signer.GenerateKeyPair(out byte[] publicKey, out byte[] secretKey);

// Sign a message
byte[] message = System.Text.Encoding.UTF8.GetBytes("Hello, World!");
byte[] signature = signer.Sign(message, secretKey);

// Verify the signature
bool isValid = signer.Verify(signature, publicKey, out byte[] recoveredMessage);

if (isValid)
{
    Console.WriteLine("Signature valid!");
    Console.WriteLine($"Message: {System.Text.Encoding.UTF8.GetString(recoveredMessage)}");
}
```

## Security Levels

| Level | Secret Key | Public Key | Signature Overhead | Hash |
|-------|------------|------------|-------------------|------|
| 128 | 32 bytes | 54 bytes | 162 bytes | SHA-256 |
| 192 | 50 bytes | 88 bytes | 264 bytes | SHA-384 |
| 256 | 64 bytes | 118 bytes | 356 bytes | SHA-512 |

## API Reference

### KazSigner Class

```csharp
// Constructor
KazSigner(SecurityLevel level, bool autoInitialize = true)

// Properties
SecurityLevel Level { get; }
int SecretKeyBytes { get; }
int PublicKeyBytes { get; }
int SignatureOverhead { get; }
int HashBytes { get; }

// Methods
void Initialize()
bool IsInitialized()
void GenerateKeyPair(out byte[] publicKey, out byte[] secretKey)
byte[] Sign(byte[] message, byte[] secretKey)
bool Verify(byte[] signature, byte[] publicKey, out byte[] message)
byte[] Hash(byte[] message)
string GetVersion()
int GetVersionNumber()
void Dispose()
```

### SecurityLevel Enum

```csharp
enum SecurityLevel
{
    Level128 = 128,  // 128-bit security (SHA-256)
    Level192 = 192,  // 192-bit security (SHA-384)
    Level256 = 256   // 256-bit security (SHA-512)
}
```

### Error Handling

Operations throw `KazSignException` on failure:

```csharp
try
{
    signer.GenerateKeyPair(out var pk, out var sk);
}
catch (KazSignException ex)
{
    Console.WriteLine($"Error: {ex.ErrorCode} - {ex.Message}");
}
```

## Native Library Location

The P/Invoke bindings look for the native library in these locations:

1. Current directory
2. Application directory
3. System library paths (`LD_LIBRARY_PATH`, `DYLD_LIBRARY_PATH`)
4. Packaged `runtimes/{rid}/native/` directory

For development, ensure the shared libraries are in your build output directory or set the appropriate environment variable:

```bash
# macOS
export DYLD_LIBRARY_PATH=/path/to/combined/build/lib:$DYLD_LIBRARY_PATH

# Linux
export LD_LIBRARY_PATH=/path/to/combined/build/lib:$LD_LIBRARY_PATH
```

## NuGet Package

To create a NuGet package including native libraries:

```bash
cd KazSign
dotnet pack -c Release
```

The package will include native libraries from `build/lib/` for macOS, Linux, and Windows.
