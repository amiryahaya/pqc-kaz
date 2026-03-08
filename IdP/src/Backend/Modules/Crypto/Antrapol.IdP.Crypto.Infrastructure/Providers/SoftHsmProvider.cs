using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Antrapol.IdP.Crypto.Domain.Enums;
using Antrapol.IdP.Crypto.Domain.Interfaces;

namespace Antrapol.IdP.Crypto.Infrastructure.Providers;

/// <summary>
/// HSM provider implementation using SoftHSM2 via PKCS#11.
/// Suitable for development and testing environments.
/// </summary>
public sealed partial class SoftHsmProvider : IHsmProvider, IDisposable
{
    private readonly SoftHsmOptions _options;
    private readonly ILogger<SoftHsmProvider> _logger;
    private readonly KazSignProvider _kazSignProvider;
    private IPkcs11Library? _pkcs11Library;
    private ISlot? _slot;
    private bool _disposed;

    // LoggerMessage delegates for high-performance logging
    [LoggerMessage(Level = LogLevel.Information, Message = "Generated KAZ-SIGN-256 keypair with label {Label}, handle {Handle}")]
    private partial void LogKeyPairGenerated(string label, string handle);

    [LoggerMessage(Level = LogLevel.Debug, Message = "Signing {DataLength} bytes with key {KeyHandle}")]
    private partial void LogSigning(int dataLength, string keyHandle);

    [LoggerMessage(Level = LogLevel.Debug, Message = "Verifying signature for {DataLength} bytes with key {KeyHandle}")]
    private partial void LogVerifying(int dataLength, string keyHandle);

    [LoggerMessage(Level = LogLevel.Debug, Message = "Encapsulating with key {KeyHandle}")]
    private partial void LogEncapsulating(string keyHandle);

    [LoggerMessage(Level = LogLevel.Debug, Message = "Decapsulating {CiphertextLength} bytes with key {KeyHandle}")]
    private partial void LogDecapsulating(int ciphertextLength, string keyHandle);

    [LoggerMessage(Level = LogLevel.Information, Message = "Destroying key {KeyHandle}")]
    private partial void LogDestroyingKey(string keyHandle);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Failed to get HSM info, returning defaults")]
    private partial void LogGetInfoFailed(Exception ex);

    [LoggerMessage(Level = LogLevel.Information, Message = "Connected to SoftHSM token: {TokenLabel}")]
    private partial void LogTokenConnected(string tokenLabel);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Token {TokenLabel} not found. Available tokens: {AvailableTokens}")]
    private partial void LogTokenNotFound(string tokenLabel, string availableTokens);

    [LoggerMessage(Level = LogLevel.Error, Message = "Failed to initialize PKCS#11 library at {LibraryPath}")]
    private partial void LogInitializationFailed(Exception ex, string libraryPath);

    public SoftHsmProvider(
        IOptions<SoftHsmOptions> options,
        ILogger<SoftHsmProvider> logger,
        KazSignProvider kazSignProvider)
    {
        _options = options.Value;
        _logger = logger;
        _kazSignProvider = kazSignProvider;
    }

    public async Task<HsmKeyResult> GenerateKeyPairAsync(
        string label,
        KeyAlgorithm algorithm,
        CancellationToken ct = default)
    {
        ValidateSignatureAlgorithm(algorithm);

        return await Task.Run(() =>
        {
            // For KAZ-SIGN algorithms, we use the native library
            // and store the key reference in the HSM
            var keyPair = _kazSignProvider.GenerateKeyPair();

            // In a real HSM, we would store the private key in the HSM
            // and return a handle. For SoftHSM development, we'll store
            // the key material wrapped in the PKCS#11 token.

            // For now, return the public key with a generated handle
            var keyHandle = $"kaz-sign:{Guid.CreateVersion7():N}";

            LogKeyPairGenerated(label, keyHandle);

            return new HsmKeyResult(keyHandle, keyPair.PublicKey);
        }, ct);
    }

    public Task<byte[]> SignAsync(
        string keyHandle,
        byte[] data,
        KeyAlgorithm algorithm,
        CancellationToken ct = default)
    {
        ValidateSignatureAlgorithm(algorithm);
        ArgumentException.ThrowIfNullOrEmpty(keyHandle);
        ArgumentNullException.ThrowIfNull(data);

        LogSigning(data.Length, keyHandle);

        // This is a placeholder - in real implementation,
        // we would load the secret key from PKCS#11 token
        throw new NotImplementedException(
            "HSM signing requires key material stored in the HSM. " +
            "Use the native KazSignProvider for direct signing.");
    }

    public Task<bool> VerifyAsync(
        string keyHandle,
        byte[] data,
        byte[] signature,
        KeyAlgorithm algorithm,
        CancellationToken ct = default)
    {
        ValidateSignatureAlgorithm(algorithm);
        ArgumentException.ThrowIfNullOrEmpty(keyHandle);
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(signature);

        LogVerifying(data.Length, keyHandle);

        // In production, retrieve public key from HSM
        // For now, this requires the public key to be passed separately
        throw new NotImplementedException(
            "HSM verification requires public key from HSM. " +
            "Use the native KazSignProvider for direct verification.");
    }

    public Task<EncapsulationResult> EncapsulateAsync(
        string keyHandle,
        KeyAlgorithm algorithm,
        CancellationToken ct = default)
    {
        ValidateKemAlgorithm(algorithm);
        ArgumentException.ThrowIfNullOrEmpty(keyHandle);

        LogEncapsulating(keyHandle);

        // Placeholder for KEM encapsulation
        throw new NotImplementedException(
            "KEM encapsulation in HSM is not yet implemented.");
    }

    public Task<byte[]> DecapsulateAsync(
        string keyHandle,
        byte[] ciphertext,
        KeyAlgorithm algorithm,
        CancellationToken ct = default)
    {
        ValidateKemAlgorithm(algorithm);
        ArgumentException.ThrowIfNullOrEmpty(keyHandle);
        ArgumentNullException.ThrowIfNull(ciphertext);

        LogDecapsulating(ciphertext.Length, keyHandle);

        // Placeholder for KEM decapsulation
        throw new NotImplementedException(
            "KEM decapsulation in HSM is not yet implemented.");
    }

    public async Task DestroyKeyAsync(string keyHandle, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(keyHandle);

        await Task.Run(() =>
        {
            LogDestroyingKey(keyHandle);

            // In production, delete the key from PKCS#11 token
            // For SoftHSM, we would find and destroy the object
        }, ct);
    }

    public async Task<bool> KeyExistsAsync(string keyHandle, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(keyHandle);

        return await Task.Run(() =>
        {
            // Check if key exists in the token
            // For now, return false as keys are managed differently
            return false;
        }, ct);
    }

    public async Task<HsmInfo> GetInfoAsync(CancellationToken ct = default)
    {
        return await Task.Run(() =>
        {
            try
            {
                EnsureInitialized();

                if (_slot != null)
                {
                    var tokenInfo = _slot.GetTokenInfo();
                    return new HsmInfo(
                        Manufacturer: tokenInfo.ManufacturerId.Trim(),
                        Model: tokenInfo.Model.Trim(),
                        SerialNumber: tokenInfo.SerialNumber.Trim(),
                        FirmwareVersion: tokenInfo.FirmwareVersion,
                        IsInitialized: tokenInfo.TokenFlags.TokenInitialized);
                }

                // Return SoftHSM defaults if not initialized
                return new HsmInfo(
                    Manufacturer: "SoftHSM Project",
                    Model: "SoftHSM v2",
                    SerialNumber: "Development",
                    FirmwareVersion: "2.0",
                    IsInitialized: false);
            }
            catch (Exception ex)
            {
                LogGetInfoFailed(ex);
                return new HsmInfo(
                    Manufacturer: "SoftHSM Project",
                    Model: "SoftHSM v2",
                    SerialNumber: "Development",
                    FirmwareVersion: "2.0",
                    IsInitialized: false);
            }
        }, ct);
    }

    private void EnsureInitialized()
    {
        if (_pkcs11Library != null)
            return;

        try
        {
            var factories = new Pkcs11InteropFactories();
            _pkcs11Library = factories.Pkcs11LibraryFactory.LoadPkcs11Library(
                factories,
                _options.LibraryPath,
                AppType.MultiThreaded);

            // Find the slot with our token
            var slots = _pkcs11Library.GetSlotList(SlotsType.WithTokenPresent);
            _slot = slots.FirstOrDefault(s =>
            {
                var tokenInfo = s.GetTokenInfo();
                return tokenInfo.Label.Trim() == _options.TokenLabel;
            });

            if (_slot != null)
            {
                LogTokenConnected(_options.TokenLabel);
            }
            else
            {
                var availableTokens = string.Join(", ", slots.Select(s => s.GetTokenInfo().Label.Trim()));
                LogTokenNotFound(_options.TokenLabel, availableTokens);
            }
        }
        catch (Exception ex)
        {
            LogInitializationFailed(ex, _options.LibraryPath);
            throw;
        }
    }

    private static void ValidateSignatureAlgorithm(KeyAlgorithm algorithm)
    {
        if (algorithm is not (KeyAlgorithm.KazSign128 or KeyAlgorithm.KazSign192 or KeyAlgorithm.KazSign256))
        {
            throw new ArgumentException(
                $"Invalid signature algorithm: {algorithm}. Expected KAZ-SIGN variant.",
                nameof(algorithm));
        }
    }

    private static void ValidateKemAlgorithm(KeyAlgorithm algorithm)
    {
        if (algorithm is not (KeyAlgorithm.KazKem128 or KeyAlgorithm.KazKem192 or KeyAlgorithm.KazKem256))
        {
            throw new ArgumentException(
                $"Invalid KEM algorithm: {algorithm}. Expected KAZ-KEM variant.",
                nameof(algorithm));
        }
    }

    public void Dispose()
    {
        if (_disposed)
            return;

        _pkcs11Library?.Dispose();
        _pkcs11Library = null;
        _slot = null;
        _disposed = true;
    }
}

/// <summary>
/// Configuration options for SoftHSM provider.
/// </summary>
public sealed class SoftHsmOptions
{
    /// <summary>
    /// Path to the SoftHSM2 PKCS#11 library.
    /// Default paths:
    /// - Linux: /usr/lib/softhsm/libsofthsm2.so
    /// - macOS: /usr/local/lib/softhsm/libsofthsm2.so
    /// - Docker: /usr/lib/softhsm/libsofthsm2.so
    /// </summary>
    public string LibraryPath { get; set; } = GetDefaultLibraryPath();

    /// <summary>
    /// Token label to use for operations.
    /// Must match the label used when initializing the token.
    /// </summary>
    public string TokenLabel { get; set; } = "idp-dev-token";

    /// <summary>
    /// User PIN for the token.
    /// </summary>
    public string UserPin { get; set; } = "87654321";

    /// <summary>
    /// Security Officer PIN for the token (used for admin operations).
    /// </summary>
    public string SoPin { get; set; } = "12345678";

    private static string GetDefaultLibraryPath()
    {
        // Try common SoftHSM2 library paths
        var paths = new[]
        {
            "/usr/lib/softhsm/libsofthsm2.so",           // Linux (Alpine, Debian)
            "/usr/local/lib/softhsm/libsofthsm2.so",    // macOS (Homebrew)
            "/opt/homebrew/lib/softhsm/libsofthsm2.so", // macOS (Apple Silicon Homebrew)
            "C:\\SoftHSM2\\lib\\softhsm2.dll",          // Windows
            "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so", // Ubuntu/Debian x64
        };

        foreach (var path in paths)
        {
            if (File.Exists(path))
                return path;
        }

        // Default to Linux path (will fail gracefully if not found)
        return "/usr/lib/softhsm/libsofthsm2.so";
    }
}
