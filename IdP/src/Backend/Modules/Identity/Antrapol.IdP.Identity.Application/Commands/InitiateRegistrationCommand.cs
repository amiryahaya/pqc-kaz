using Antrapol.IdP.Identity.Domain.Enums;

namespace Antrapol.IdP.Identity.Application.Commands;

/// <summary>
/// Command to initiate user registration.
/// Collects user profile data and sends email OTP for verification.
/// </summary>
public sealed record InitiateRegistrationCommand(
    // User Profile
    string FullName,
    string MyKadNumber,
    string Email,
    string PhoneNumber,
    // Device Info
    string? DeviceId = null,
    string? DeviceName = null,
    DevicePlatform? DevicePlatform = null,
    string? DeviceOsVersion = null,
    string? AppVersion = null);
