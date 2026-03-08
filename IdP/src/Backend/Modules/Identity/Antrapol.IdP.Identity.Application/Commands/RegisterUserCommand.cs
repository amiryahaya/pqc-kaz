namespace Antrapol.IdP.Identity.Application.Commands;

public sealed record RegisterUserCommand(
    string Email,
    string? DisplayName);
