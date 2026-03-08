using Antrapol.IdP.Identity.Application.DTOs;
using Antrapol.IdP.Identity.Application.Interfaces;
using Antrapol.IdP.Identity.Domain.Entities;
using Antrapol.IdP.Identity.Domain.Enums;
using Antrapol.IdP.Identity.Domain.Interfaces;
using Antrapol.IdP.SharedKernel.Handlers;
using Antrapol.IdP.SharedKernel.Results;

namespace Antrapol.IdP.Identity.Application.Commands;

public sealed class SubmitCsrCommandHandler : ICommandHandler<SubmitCsrCommand, SubmitCsrDto>
{
    private readonly IPendingRegistrationRepository _registrationRepository;
    private readonly ICsrRequestRepository _csrRepository;
    private readonly IKeyShareRepository _keyShareRepository;
    private readonly ICsrService _csrService;

    public SubmitCsrCommandHandler(
        IPendingRegistrationRepository registrationRepository,
        ICsrRequestRepository csrRepository,
        IKeyShareRepository keyShareRepository,
        ICsrService csrService)
    {
        _registrationRepository = registrationRepository;
        _csrRepository = csrRepository;
        _keyShareRepository = keyShareRepository;
        _csrService = csrService;
    }

    public async Task<Result<SubmitCsrDto>> HandleAsync(
        SubmitCsrCommand command,
        CancellationToken ct = default)
    {
        // Get registration
        var registration = await _registrationRepository.GetByIdAsync(command.RegistrationId, ct);
        if (registration is null)
        {
            return Error.NotFound("Registration.NotFound", "Registration not found.");
        }

        // Validate state
        if (registration.Status != RegistrationStatus.PhoneVerified)
        {
            return Error.Validation("Registration.InvalidState",
                "Both email and phone must be verified before submitting CSR.");
        }

        // Parse and validate Device CSR
        var deviceCsrResult = _csrService.ParseCsr(command.DeviceCsr);
        if (deviceCsrResult.IsFailure)
        {
            return Error.Validation("CSR.InvalidDeviceCsr",
                $"Invalid device CSR: {deviceCsrResult.Error.Message}");
        }
        var deviceCsrInfo = deviceCsrResult.Value;

        // Verify Device CSR signature
        if (!_csrService.VerifyCsrSignature(command.DeviceCsr))
        {
            return Error.Validation("CSR.InvalidDeviceSignature",
                "Device CSR signature verification failed.");
        }

        // Parse and validate User CSR
        var userCsrResult = _csrService.ParseCsr(command.UserCsr);
        if (userCsrResult.IsFailure)
        {
            return Error.Validation("CSR.InvalidUserCsr",
                $"Invalid user CSR: {userCsrResult.Error.Message}");
        }
        var userCsrInfo = userCsrResult.Value;

        // Verify User CSR signature
        if (!_csrService.VerifyCsrSignature(command.UserCsr))
        {
            return Error.Validation("CSR.InvalidUserSignature",
                "User CSR signature verification failed.");
        }

        // Verify payload signature (signed by device private key)
        var payloadBytes = System.Text.Encoding.UTF8.GetBytes(
            $"{command.DeviceCsr}|{command.UserCsr}|{command.EncryptedPartControl.Ciphertext}|{command.EncryptedPartRecovery.Ciphertext}");
        var signatureBytes = Convert.FromBase64String(command.PayloadSignature);

        if (!_csrService.VerifySignature(deviceCsrInfo.PublicKey, payloadBytes, signatureBytes))
        {
            return Error.Validation("CSR.InvalidPayloadSignature",
                "Payload signature verification failed. The payload must be signed by the device private key.");
        }

        // Check for duplicate public keys
        var existingDeviceCsr = await _csrRepository.GetByPublicKeyFingerprintAsync(
            deviceCsrInfo.PublicKeyFingerprint, ct);
        if (existingDeviceCsr is not null)
        {
            return Error.Conflict("CSR.DuplicateDeviceKey",
                "A CSR with this device public key already exists.");
        }

        var existingUserCsr = await _csrRepository.GetByPublicKeyFingerprintAsync(
            userCsrInfo.PublicKeyFingerprint, ct);
        if (existingUserCsr is not null)
        {
            return Error.Conflict("CSR.DuplicateUserKey",
                "A CSR with this user public key already exists.");
        }

        // Create Device CSR record
        var deviceCsr = CsrRequest.Create(
            registrationId: command.RegistrationId,
            type: CsrType.Device,
            csrData: deviceCsrInfo.CsrData,
            subjectDn: deviceCsrInfo.SubjectDn,
            publicKey: deviceCsrInfo.PublicKey,
            publicKeyFingerprint: deviceCsrInfo.PublicKeyFingerprint);

        // Create User CSR record
        var userCsr = CsrRequest.Create(
            registrationId: command.RegistrationId,
            type: CsrType.User,
            csrData: userCsrInfo.CsrData,
            subjectDn: userCsrInfo.SubjectDn,
            publicKey: userCsrInfo.PublicKey,
            publicKeyFingerprint: userCsrInfo.PublicKeyFingerprint);

        // Store CSRs
        await _csrRepository.CreateAsync(deviceCsr, ct);
        await _csrRepository.CreateAsync(userCsr, ct);

        // Store key shares associated with registration (will be linked to user after completion)
        var controlShare = KeyShare.CreateControlShare(
            registrationId: command.RegistrationId,
            encryptedData: Convert.FromBase64String(command.EncryptedPartControl.Ciphertext),
            encapsulatedKey: Convert.FromBase64String(command.EncryptedPartControl.EncapsulatedKey ?? ""),
            shareIndex: 2); // part_control is index 2

        var recoveryShare = KeyShare.CreateRecoveryShare(
            registrationId: command.RegistrationId,
            encryptedData: Convert.FromBase64String(command.EncryptedPartRecovery.Ciphertext),
            nonce: Convert.FromBase64String(command.EncryptedPartRecovery.Nonce ?? ""),
            authTag: Convert.FromBase64String(command.EncryptedPartRecovery.AuthTag ?? ""),
            salt: Convert.FromBase64String(command.EncryptedPartRecovery.Salt ?? ""),
            shareIndex: 3); // part_recovery is index 3

        await _keyShareRepository.CreateAsync(controlShare, ct);
        await _keyShareRepository.CreateAsync(recoveryShare, ct);

        // Update registration status
        registration.MarkCsrSubmitted();
        await _registrationRepository.UpdateAsync(registration, ct);

        return new SubmitCsrDto(
            registration.TrackingId,
            deviceCsr.Id,
            userCsr.Id,
            registration.Status,
            "CSR submitted successfully. Certificates will be issued shortly.");
    }
}
