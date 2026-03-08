using System;
using System.Security.Cryptography;

namespace Antrapol.Kaz.Kem;

/// <summary>
/// Represents a KAZ-KEM key pair (public + private key).
/// </summary>
public sealed class KazKemKeyPair : IDisposable
{
    private byte[]? _publicKey;
    private byte[]? _privateKey;
    private bool _disposed;

    /// <summary>
    /// The security level this key pair was generated for.
    /// </summary>
    public SecurityLevel SecurityLevel { get; }

    /// <summary>
    /// The public key bytes (read-only copy).
    /// </summary>
    public ReadOnlySpan<byte> PublicKey
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _publicKey.AsSpan();
        }
    }

    /// <summary>
    /// The private key bytes (read-only copy).
    /// WARNING: Handle with care - this is sensitive cryptographic material.
    /// </summary>
    public ReadOnlySpan<byte> PrivateKey
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _privateKey.AsSpan();
        }
    }

    /// <summary>
    /// Public key size in bytes.
    /// </summary>
    public int PublicKeySize => _publicKey?.Length ?? 0;

    /// <summary>
    /// Private key size in bytes.
    /// </summary>
    public int PrivateKeySize => _privateKey?.Length ?? 0;

    internal KazKemKeyPair(byte[] publicKey, byte[] privateKey, SecurityLevel level)
    {
        _publicKey = publicKey;
        _privateKey = privateKey;
        SecurityLevel = level;
    }

    /// <summary>
    /// Export the public key as a new byte array.
    /// </summary>
    public byte[] ExportPublicKey()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _publicKey!.ToArray();
    }

    /// <summary>
    /// Export the private key as a new byte array.
    /// WARNING: Handle with care - this is sensitive cryptographic material.
    /// </summary>
    public byte[] ExportPrivateKey()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _privateKey!.ToArray();
    }

    /// <summary>
    /// Create a public-key-only version for sharing.
    /// </summary>
    public KazKemPublicKey GetPublicKey()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return new KazKemPublicKey(_publicKey!.ToArray(), SecurityLevel);
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            // Securely clear private key from memory
            if (_privateKey != null)
            {
                CryptographicOperations.ZeroMemory(_privateKey);
                _privateKey = null;
            }
            _publicKey = null;
            _disposed = true;
        }
    }
}

/// <summary>
/// Represents a KAZ-KEM public key (shareable).
/// </summary>
public sealed class KazKemPublicKey
{
    private readonly byte[] _publicKey;

    /// <summary>
    /// The security level this key was generated for.
    /// </summary>
    public SecurityLevel SecurityLevel { get; }

    /// <summary>
    /// The public key bytes (read-only).
    /// </summary>
    public ReadOnlySpan<byte> Bytes => _publicKey.AsSpan();

    /// <summary>
    /// Public key size in bytes.
    /// </summary>
    public int Size => _publicKey.Length;

    internal KazKemPublicKey(byte[] publicKey, SecurityLevel level)
    {
        _publicKey = publicKey;
        SecurityLevel = level;
    }

    /// <summary>
    /// Create a public key from raw bytes.
    /// </summary>
    public static KazKemPublicKey FromBytes(ReadOnlySpan<byte> bytes, SecurityLevel level)
    {
        return new KazKemPublicKey(bytes.ToArray(), level);
    }

    /// <summary>
    /// Export the public key as a new byte array.
    /// </summary>
    public byte[] Export()
    {
        return _publicKey.ToArray();
    }
}

/// <summary>
/// Represents encapsulation result (ciphertext + shared secret).
/// </summary>
public sealed class KazKemEncapsulationResult : IDisposable
{
    private byte[]? _ciphertext;
    private byte[]? _sharedSecret;
    private bool _disposed;

    /// <summary>
    /// The ciphertext to send to the key holder.
    /// </summary>
    public ReadOnlySpan<byte> Ciphertext
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _ciphertext.AsSpan();
        }
    }

    /// <summary>
    /// The shared secret (keep this secret!).
    /// </summary>
    public ReadOnlySpan<byte> SharedSecret
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _sharedSecret.AsSpan();
        }
    }

    /// <summary>
    /// Ciphertext size in bytes.
    /// </summary>
    public int CiphertextSize => _ciphertext?.Length ?? 0;

    /// <summary>
    /// Shared secret size in bytes.
    /// </summary>
    public int SharedSecretSize => _sharedSecret?.Length ?? 0;

    internal KazKemEncapsulationResult(byte[] ciphertext, byte[] sharedSecret)
    {
        _ciphertext = ciphertext;
        _sharedSecret = sharedSecret;
    }

    /// <summary>
    /// Export ciphertext as a new byte array.
    /// </summary>
    public byte[] ExportCiphertext()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _ciphertext!.ToArray();
    }

    /// <summary>
    /// Export shared secret as a new byte array.
    /// </summary>
    public byte[] ExportSharedSecret()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _sharedSecret!.ToArray();
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            // Securely clear shared secret from memory
            if (_sharedSecret != null)
            {
                CryptographicOperations.ZeroMemory(_sharedSecret);
                _sharedSecret = null;
            }
            _ciphertext = null;
            _disposed = true;
        }
    }
}
