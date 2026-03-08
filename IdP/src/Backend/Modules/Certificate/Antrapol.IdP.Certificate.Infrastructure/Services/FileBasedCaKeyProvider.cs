using Microsoft.Extensions.Options;
using Antrapol.IdP.Crypto.Infrastructure.Providers;

namespace Antrapol.IdP.Certificate.Infrastructure.Services;

/// <summary>
/// File-based CA key provider for development/testing.
/// In production, use HSM-based provider.
/// </summary>
public sealed class FileBasedCaKeyProvider : ICaKeyProvider, IDisposable
{
    private readonly CaKeyOptions _options;
    private readonly KazSignProvider _kazSignProvider;
    private byte[]? _publicKey;
    private byte[]? _secretKey;
    private readonly SemaphoreSlim _lock = new(1, 1);
    private bool _disposed;

    public FileBasedCaKeyProvider(
        IOptions<CaKeyOptions> options,
        KazSignProvider kazSignProvider)
    {
        _options = options.Value;
        _kazSignProvider = kazSignProvider;
    }

    public async Task<(byte[] PublicKey, byte[] SecretKey, string IssuerDn)> GetCaKeysAsync(CancellationToken ct = default)
    {
        await _lock.WaitAsync(ct);
        try
        {
            if (_publicKey is not null && _secretKey is not null)
            {
                return (_publicKey, _secretKey, _options.IssuerDn);
            }

            // Try to load from files
            if (File.Exists(_options.PublicKeyPath) && File.Exists(_options.SecretKeyPath))
            {
                _publicKey = await File.ReadAllBytesAsync(_options.PublicKeyPath, ct);
                _secretKey = await File.ReadAllBytesAsync(_options.SecretKeyPath, ct);
            }
            else
            {
                // Generate new CA keypair for development
                var keyPair = _kazSignProvider.GenerateKeyPair();
                _publicKey = keyPair.PublicKey;
                _secretKey = keyPair.SecretKey;

                // Save to files (development only - NEVER do this in production!)
                var directory = Path.GetDirectoryName(_options.PublicKeyPath);
                if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
                {
                    Directory.CreateDirectory(directory);
                }

                await File.WriteAllBytesAsync(_options.PublicKeyPath, _publicKey, ct);
                await File.WriteAllBytesAsync(_options.SecretKeyPath, _secretKey, ct);
            }

            return (_publicKey, _secretKey, _options.IssuerDn);
        }
        finally
        {
            _lock.Release();
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _lock.Dispose();
        _disposed = true;
    }
}

/// <summary>
/// Configuration options for CA keys.
/// </summary>
public sealed class CaKeyOptions
{
    public const string SectionName = "CaKeys";

    /// <summary>
    /// Path to the CA public key file.
    /// </summary>
    public string PublicKeyPath { get; set; } = "./keys/ca_public.key";

    /// <summary>
    /// Path to the CA secret key file.
    /// </summary>
    public string SecretKeyPath { get; set; } = "./keys/ca_secret.key";

    /// <summary>
    /// CA Issuer Distinguished Name.
    /// </summary>
    public string IssuerDn { get; set; } = "CN=PQC Identity CA, O=Malaysia Digital ID, C=MY";
}
