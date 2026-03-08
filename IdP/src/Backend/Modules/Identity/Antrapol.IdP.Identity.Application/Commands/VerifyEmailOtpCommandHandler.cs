using Antrapol.IdP.Identity.Application.DTOs;
using Antrapol.IdP.Identity.Application.Interfaces;
using Antrapol.IdP.Identity.Domain.Interfaces;
using Antrapol.IdP.SharedKernel.Handlers;
using Antrapol.IdP.SharedKernel.Results;

namespace Antrapol.IdP.Identity.Application.Commands;

public sealed class VerifyEmailOtpCommandHandler : ICommandHandler<VerifyEmailOtpCommand, VerifyEmailOtpDto>
{
    private readonly IPendingRegistrationRepository _registrationRepository;
    private readonly IOtpService _otpService;

    public VerifyEmailOtpCommandHandler(
        IPendingRegistrationRepository registrationRepository,
        IOtpService otpService)
    {
        _registrationRepository = registrationRepository;
        _otpService = otpService;
    }

    public async Task<Result<VerifyEmailOtpDto>> HandleAsync(
        VerifyEmailOtpCommand command,
        CancellationToken ct = default)
    {
        // Get pending registration
        var registration = await _registrationRepository.GetByIdAsync(command.RegistrationId, ct);
        if (registration is null)
        {
            return Error.NotFound("Registration.NotFound", "Registration not found.");
        }

        // Check if OTP can be verified
        if (!registration.CanVerifyEmailOtp())
        {
            if (registration.IsEmailOtpExpired())
            {
                return Error.Validation("Registration.OtpExpired", "OTP has expired.");
            }

            return Error.Validation("Registration.TooManyAttempts", "Too many OTP verification attempts.");
        }

        // Verify OTP
        if (!_otpService.VerifyOtp(command.Otp, registration.EmailOtpHash))
        {
            registration.IncrementEmailOtpAttempts();
            await _registrationRepository.UpdateAsync(registration, ct);

            return Error.Validation("Registration.InvalidOtp", "Invalid OTP.");
        }

        // Mark email as verified
        registration.MarkEmailVerified();
        await _registrationRepository.UpdateAsync(registration, ct);

        // Return DTO
        return new VerifyEmailOtpDto(
            registration.Id,
            registration.Status,
            "Email verified successfully. You can now complete your registration.");
    }
}
