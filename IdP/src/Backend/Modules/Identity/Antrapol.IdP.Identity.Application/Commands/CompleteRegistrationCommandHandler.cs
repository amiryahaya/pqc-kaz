using Antrapol.IdP.Identity.Application.DTOs;
using Antrapol.IdP.Identity.Domain.Entities;
using Antrapol.IdP.Identity.Domain.Enums;
using Antrapol.IdP.Identity.Domain.Interfaces;
using Antrapol.IdP.SharedKernel.Handlers;
using Antrapol.IdP.SharedKernel.Results;

namespace Antrapol.IdP.Identity.Application.Commands;

public sealed class CompleteRegistrationCommandHandler : ICommandHandler<CompleteRegistrationCommand, CompleteRegistrationDto>
{
    private readonly IPendingRegistrationRepository _registrationRepository;
    private readonly IUserRepository _userRepository;
    private readonly ICsrRequestRepository _csrRepository;
    private readonly IKeyShareRepository _keyShareRepository;

    public CompleteRegistrationCommandHandler(
        IPendingRegistrationRepository registrationRepository,
        IUserRepository userRepository,
        ICsrRequestRepository csrRepository,
        IKeyShareRepository keyShareRepository)
    {
        _registrationRepository = registrationRepository;
        _userRepository = userRepository;
        _csrRepository = csrRepository;
        _keyShareRepository = keyShareRepository;
    }

    public async Task<Result<CompleteRegistrationDto>> HandleAsync(
        CompleteRegistrationCommand command,
        CancellationToken ct = default)
    {
        // Get pending registration
        var registration = await _registrationRepository.GetByIdAsync(command.RegistrationId, ct);
        if (registration is null)
        {
            return Error.NotFound("Registration.NotFound", "Registration not found.");
        }

        // Verify registration status - must have certificates issued
        if (registration.Status != RegistrationStatus.CertificatesIssued)
        {
            return Error.Validation(
                "Registration.InvalidStatus",
                "Certificates must be issued before completing registration.");
        }

        // Check if user already exists (race condition check)
        if (await _userRepository.ExistsAsync(registration.Email, ct))
        {
            return Error.Conflict("Registration.UserExists", "A user with this email already exists.");
        }

        if (await _userRepository.ExistsByMyKadAsync(registration.MyKadNumber, ct))
        {
            return Error.Conflict("Registration.MyKadExists", "A user with this MyKad number already exists.");
        }

        // Create user with all profile data from registration
        var user = User.Create(
            fullName: registration.FullName,
            myKadNumber: registration.MyKadNumber,
            email: registration.Email,
            phoneNumber: registration.PhoneNumber,
            displayName: registration.FullName);

        // Mark email and phone as verified (since they were verified via OTP)
        user.VerifyEmail();
        if (registration.PhoneNumber is not null)
        {
            user.VerifyPhone();
        }

        // Register device if device info was provided
        if (registration.DeviceId is not null && registration.DeviceName is not null && registration.DevicePlatform is not null)
        {
            // Get device CSR to get the public key fingerprint
            var csrs = await _csrRepository.GetByRegistrationIdAsync(registration.Id, ct);
            var deviceCsr = csrs.FirstOrDefault(c => c.Type == CsrType.Device);

            if (deviceCsr is not null)
            {
                var device = UserDevice.Create(
                    userId: user.Id,
                    deviceId: registration.DeviceId,
                    deviceName: registration.DeviceName,
                    platform: registration.DevicePlatform.Value,
                    publicKeyFingerprint: deviceCsr.PublicKeyFingerprint,
                    osVersion: registration.DeviceOsVersion,
                    appVersion: registration.AppVersion);

                user.RegisterDevice(device);
            }
        }

        // Persist user
        await _userRepository.CreateAsync(user, ct);

        // Update key shares to reference the user (link by registration ID)
        var keyShares = await _keyShareRepository.GetByRegistrationIdAsync(registration.Id, ct);
        foreach (var keyShare in keyShares)
        {
            keyShare.LinkToUser(user.Id);
            await _keyShareRepository.UpdateAsync(keyShare, ct);
        }

        // Mark registration as completed
        registration.MarkCompleted();
        await _registrationRepository.UpdateAsync(registration, ct);

        // Return DTO
        return new CompleteRegistrationDto(
            user.Id,
            user.Email.Value,
            user.FullName,
            user.DisplayName,
            "Registration completed successfully. Your Digital ID is now active.");
    }
}
