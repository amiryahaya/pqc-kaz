using Antrapol.IdP.Identity.Application.DTOs;
using Antrapol.IdP.Identity.Application.Interfaces;
using Antrapol.IdP.Identity.Domain.Enums;
using Antrapol.IdP.Identity.Domain.Interfaces;
using Antrapol.IdP.Identity.Domain.ValueObjects;
using Antrapol.IdP.SharedKernel.Handlers;
using Antrapol.IdP.SharedKernel.Results;

namespace Antrapol.IdP.Identity.Application.Commands;

public sealed class SendPhoneOtpCommandHandler : ICommandHandler<SendPhoneOtpCommand, SendPhoneOtpDto>
{
    private readonly IPendingRegistrationRepository _registrationRepository;
    private readonly IOtpService _otpService;

    public SendPhoneOtpCommandHandler(
        IPendingRegistrationRepository registrationRepository,
        IOtpService otpService)
    {
        _registrationRepository = registrationRepository;
        _otpService = otpService;
    }

    public async Task<Result<SendPhoneOtpDto>> HandleAsync(
        SendPhoneOtpCommand command,
        CancellationToken ct = default)
    {
        // Get registration
        var registration = await _registrationRepository.GetByIdAsync(command.RegistrationId, ct);
        if (registration is null)
        {
            return Error.NotFound("Registration.NotFound", "Registration not found.");
        }

        // Validate state
        if (registration.Status != RegistrationStatus.EmailVerified)
        {
            return Error.Validation("Registration.InvalidState",
                "Email must be verified before phone verification can proceed.");
        }

        // Validate phone number exists
        if (registration.PhoneNumber is null)
        {
            return Error.Validation("Registration.NoPhone",
                "Phone number was not provided during registration.");
        }

        // Generate phone OTP
        var otp = _otpService.GenerateOtp();
        var otpHash = _otpService.HashOtp(otp);

        // Set phone OTP on registration
        registration.SetPhoneOtp(
            registration.PhoneNumber,
            otpHash,
            TimeSpan.FromMinutes(5)); // Phone OTP valid for 5 minutes

        // Persist
        await _registrationRepository.UpdateAsync(registration, ct);

        // Send SMS OTP
        await _otpService.SendSmsOtpAsync(registration.PhoneNumber.Value, otp, ct);

        return new SendPhoneOtpDto(
            registration.Id,
            registration.PhoneNumber.Value,
            registration.PhoneOtpExpiresAt!.Value);
    }
}
