namespace Antrapol.IdP.Identity.Application.Commands;

/// <summary>
/// Command to complete registration after certificates have been issued.
/// Creates the user account and activates the identity.
/// </summary>
public sealed record CompleteRegistrationCommand(Guid RegistrationId);
