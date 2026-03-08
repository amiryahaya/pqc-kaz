using Antrapol.IdP.Identity.Application.DTOs;
using Antrapol.IdP.Identity.Application.Interfaces;
using Antrapol.IdP.Identity.Domain.Enums;
using Antrapol.IdP.Identity.Domain.Interfaces;
using Antrapol.IdP.SharedKernel.Handlers;
using Antrapol.IdP.SharedKernel.Results;

namespace Antrapol.IdP.Identity.Application.Commands;

public sealed class VerifyPhoneOtpCommandHandler : ICommandHandler<VerifyPhoneOtpCommand, VerifyPhoneOtpDto>
{
    private readonly IPendingRegistrationRepository _registrationRepository;
    private readonly IOtpService _otpService;

    public VerifyPhoneOtpCommandHandler(
        IPendingRegistrationRepository registrationRepository,
        IOtpService otpService)
    {
        _registrationRepository = registrationRepository;
        _otpService = otpService;
    }

    public async Task<Result<VerifyPhoneOtpDto>> HandleAsync(
        VerifyPhoneOtpCommand command,
        CancellationToken ct = default)
    {
        // Get registration
        var registration = await _registrationRepository.GetByIdAsync(command.RegistrationId, ct);
        if (registration is null)
        {
            return Error.NotFound("Registration.NotFound", "Registration not found.");
        }

        // Validate can verify
        if (!registration.CanVerifyPhoneOtp())
        {
            if (registration.Status != RegistrationStatus.EmailVerified)
            {
                return Error.Validation("Registration.InvalidState",
                    "Registration is not in a valid state for phone verification.");
            }

            if (registration.IsPhoneOtpExpired())
            {
                return Error.Validation("Registration.OtpExpired",
                    "Phone OTP has expired. Please request a new one.");
            }

            return Error.Validation("Registration.TooManyAttempts",
                "Too many failed attempts. Please request a new OTP.");
        }

        // Verify OTP
        if (registration.PhoneOtpHash is null ||
            !_otpService.VerifyOtp(command.Otp, registration.PhoneOtpHash))
        {
            registration.IncrementPhoneOtpAttempts();
            await _registrationRepository.UpdateAsync(registration, ct);

            return Error.Validation("Registration.InvalidOtp", "Invalid OTP.");
        }

        // Mark phone as verified
        registration.MarkPhoneVerified();
        await _registrationRepository.UpdateAsync(registration, ct);

        return new VerifyPhoneOtpDto(
            registration.Id,
            registration.Status,
            "Phone verified successfully. You may now submit CSR for certificate issuance.");
    }
}
