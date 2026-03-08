using Antrapol.IdP.SharedKernel.Results;

namespace Antrapol.IdP.Identity.Application.Interfaces;

/// <summary>
/// Service for managing recovery tokens.
/// Recovery tokens are used for emergency account recovery using Shamir's secret sharing.
/// </summary>
public interface IRecoveryTokenService
{
    /// <summary>
    /// Generates a new recovery token for a user.
    /// </summary>
    /// <param name="userId">User ID</param>
    /// <param name="keyShareId">ID of the associated recovery key share</param>
    /// <param name="ct">Cancellation token</param>
    /// <returns>Result containing the generated recovery token (to be saved by user)</returns>
    Task<Result<RecoveryTokenResult>> GenerateTokenAsync(
        Guid userId,
        Guid keyShareId,
        CancellationToken ct = default);

    /// <summary>
    /// Verifies a recovery token hash.
    /// </summary>
    /// <param name="userId">User ID</param>
    /// <param name="tokenHash">Hash of the recovery token</param>
    /// <param name="ct">Cancellation token</param>
    /// <returns>True if valid, false otherwise</returns>
    Task<Result<bool>> VerifyTokenAsync(
        Guid userId,
        string tokenHash,
        CancellationToken ct = default);

    /// <summary>
    /// Initiates account recovery using a recovery token.
    /// </summary>
    /// <param name="request">Recovery initiation request</param>
    /// <param name="ct">Cancellation token</param>
    /// <returns>Result containing recovery session details</returns>
    Task<Result<RecoverySessionResult>> InitiateRecoveryAsync(
        RecoveryInitiationRequest request,
        CancellationToken ct = default);

    /// <summary>
    /// Completes the recovery process by setting up new device keys.
    /// </summary>
    /// <param name="request">Recovery completion request</param>
    /// <param name="ct">Cancellation token</param>
    /// <returns>Result indicating success or failure</returns>
    Task<Result<RecoveryCompletionResult>> CompleteRecoveryAsync(
        RecoveryCompletionRequest request,
        CancellationToken ct = default);

    /// <summary>
    /// Revokes all active recovery tokens for a user.
    /// </summary>
    /// <param name="userId">User ID</param>
    /// <param name="ct">Cancellation token</param>
    Task<Result<int>> RevokeAllTokensAsync(
        Guid userId,
        CancellationToken ct = default);
}

/// <summary>
/// Result of recovery token generation.
/// </summary>
/// <param name="Token">The generated recovery token (must be saved by user offline)</param>
/// <param name="TokenId">Recovery token record ID</param>
/// <param name="TokenVersion">Token version number</param>
/// <param name="Mnemonic">Optional mnemonic phrase representation of the token</param>
public sealed record RecoveryTokenResult(
    string Token,
    Guid TokenId,
    int TokenVersion,
    string? Mnemonic = null);

/// <summary>
/// Request to initiate account recovery.
/// </summary>
/// <param name="RecoveryToken">The recovery token provided by user</param>
/// <param name="Email">User's registered email</param>
/// <param name="NewDeviceId">New device identifier</param>
/// <param name="NewDeviceName">New device name</param>
/// <param name="NewDevicePlatform">New device platform</param>
/// <param name="IpAddress">Client IP address</param>
public sealed record RecoveryInitiationRequest(
    string RecoveryToken,
    string Email,
    string NewDeviceId,
    string NewDeviceName,
    string NewDevicePlatform,
    string? IpAddress = null);

/// <summary>
/// Result of recovery initiation.
/// </summary>
/// <param name="RecoverySessionId">Unique recovery session identifier</param>
/// <param name="UserId">User ID being recovered</param>
/// <param name="EncryptedPartRecovery">Encrypted recovery key share (encrypted with recovery password)</param>
/// <param name="ExpiresAt">Session expiration time</param>
public sealed record RecoverySessionResult(
    Guid RecoverySessionId,
    Guid UserId,
    byte[] EncryptedPartRecovery,
    DateTimeOffset ExpiresAt);

/// <summary>
/// Request to complete account recovery.
/// </summary>
/// <param name="RecoverySessionId">Recovery session ID</param>
/// <param name="NewDeviceCsr">CSR for new device certificate</param>
/// <param name="NewUserCsr">CSR for new user certificate</param>
/// <param name="NewEncryptedPartControl">New encrypted control key share</param>
/// <param name="NewEncryptedPartRecovery">New encrypted recovery key share</param>
public sealed record RecoveryCompletionRequest(
    Guid RecoverySessionId,
    string NewDeviceCsr,
    string NewUserCsr,
    byte[] NewEncryptedPartControl,
    byte[] NewEncryptedPartRecovery);

/// <summary>
/// Result of recovery completion.
/// </summary>
/// <param name="UserId">User ID</param>
/// <param name="NewDeviceCertificatePem">New device certificate in PEM format</param>
/// <param name="NewUserCertificatePem">New user certificate in PEM format</param>
/// <param name="NewRecoveryToken">New recovery token for future recovery</param>
public sealed record RecoveryCompletionResult(
    Guid UserId,
    string NewDeviceCertificatePem,
    string NewUserCertificatePem,
    RecoveryTokenResult NewRecoveryToken);
