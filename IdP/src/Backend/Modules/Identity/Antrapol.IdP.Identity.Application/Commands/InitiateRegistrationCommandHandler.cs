using Antrapol.IdP.Identity.Application.DTOs;
using Antrapol.IdP.Identity.Application.Interfaces;
using Antrapol.IdP.Identity.Domain.Entities;
using Antrapol.IdP.Identity.Domain.Interfaces;
using Antrapol.IdP.Identity.Domain.ValueObjects;
using Antrapol.IdP.SharedKernel.Handlers;
using Antrapol.IdP.SharedKernel.Results;

namespace Antrapol.IdP.Identity.Application.Commands;

public sealed class InitiateRegistrationCommandHandler : ICommandHandler<InitiateRegistrationCommand, InitiateRegistrationDto>
{
    private readonly IPendingRegistrationRepository _registrationRepository;
    private readonly IUserRepository _userRepository;
    private readonly IOtpService _otpService;

    public InitiateRegistrationCommandHandler(
        IPendingRegistrationRepository registrationRepository,
        IUserRepository userRepository,
        IOtpService otpService)
    {
        _registrationRepository = registrationRepository;
        _userRepository = userRepository;
        _otpService = otpService;
    }

    public async Task<Result<InitiateRegistrationDto>> HandleAsync(
        InitiateRegistrationCommand command,
        CancellationToken ct = default)
    {
        // Validate required fields
        if (string.IsNullOrWhiteSpace(command.FullName))
        {
            return Error.Validation("Registration.InvalidFullName", "Full name is required.");
        }

        if (string.IsNullOrWhiteSpace(command.MyKadNumber) || !IsValidMyKadNumber(command.MyKadNumber))
        {
            return Error.Validation("Registration.InvalidMyKad", "Invalid MyKad number format. Must be 12 digits.");
        }

        // Validate email format
        if (!Email.TryCreate(command.Email, out var email) || email is null)
        {
            return Error.Validation("Registration.InvalidEmail", "Invalid email format.");
        }

        // Validate phone number
        if (!PhoneNumber.TryCreate(command.PhoneNumber, out var phoneNumber) || phoneNumber is null)
        {
            return Error.Validation("Registration.InvalidPhone", "Invalid phone number format.");
        }

        // Check if user already exists by email
        if (await _userRepository.ExistsAsync(email, ct))
        {
            return Error.Conflict("Registration.EmailExists", "A user with this email already exists.");
        }

        // Check if user already exists by MyKad number
        if (await _userRepository.ExistsByMyKadAsync(command.MyKadNumber, ct))
        {
            return Error.Conflict("Registration.MyKadExists", "A user with this MyKad number already exists.");
        }

        // Check for existing pending registration (by email or MyKad)
        var existingByEmail = await _registrationRepository.GetByEmailAsync(email, ct);
        if (existingByEmail is not null)
        {
            await _registrationRepository.DeleteAsync(existingByEmail.Id, ct);
        }

        var existingByMyKad = await _registrationRepository.GetByMyKadAsync(command.MyKadNumber, ct);
        if (existingByMyKad is not null)
        {
            await _registrationRepository.DeleteAsync(existingByMyKad.Id, ct);
        }

        // Generate OTP
        var otp = _otpService.GenerateOtp();
        var otpHash = _otpService.HashOtp(otp);

        // Create pending registration with full profile
        var registration = PendingRegistration.Create(
            fullName: command.FullName.Trim(),
            myKadNumber: command.MyKadNumber.Replace("-", "").Trim(),
            email: email,
            emailOtpHash: otpHash,
            otpValidityDuration: TimeSpan.FromMinutes(10),
            deviceId: command.DeviceId,
            deviceName: command.DeviceName,
            devicePlatform: command.DevicePlatform,
            deviceOsVersion: command.DeviceOsVersion,
            appVersion: command.AppVersion);

        // Persist
        await _registrationRepository.CreateAsync(registration, ct);

        // Send OTP via email
        await _otpService.SendEmailOtpAsync(email.Value, otp, command.FullName, ct);

        // Return DTO
        return new InitiateRegistrationDto(
            registration.TrackingId,
            registration.Email.Value,
            registration.EmailOtpExpiresAt);
    }

    private static bool IsValidMyKadNumber(string myKad)
    {
        // Remove dashes and spaces
        var normalized = myKad.Replace("-", "").Replace(" ", "");

        // Must be exactly 12 digits
        if (normalized.Length != 12)
            return false;

        // All characters must be digits
        return normalized.All(char.IsDigit);
    }
}
