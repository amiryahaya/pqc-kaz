namespace Antrapol.IdP.Identity.Application.Commands;

/// <summary>
/// Command to submit CSRs (device and user) along with encrypted key shares.
/// This is Phase 3 of the registration flow.
/// </summary>
public sealed record SubmitCsrCommand(
    Guid RegistrationId,
    // CSRs
    string DeviceCsr,      // Base64-encoded DER
    string UserCsr,        // Base64-encoded DER
    // Encrypted key shares
    EncryptedShareDto EncryptedPartControl,    // System's share
    EncryptedShareDto EncryptedPartRecovery,   // Recovery share
    // Signature over entire payload (signed by device private key)
    string PayloadSignature);

/// <summary>
/// DTO for encrypted key share data.
/// </summary>
public sealed record EncryptedShareDto(
    string Ciphertext,           // Base64 encoded encrypted share
    string? EncapsulatedKey,     // For KEM-encrypted shares (Base64)
    string? Nonce,               // For AES-GCM encrypted shares (Base64)
    string? AuthTag,             // Authentication tag (Base64)
    string? Salt);               // Salt for key derivation (Base64)
