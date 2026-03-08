using Antrapol.IdP.Identity.Application.DTOs;
using Antrapol.IdP.Identity.Domain.Entities;
using Antrapol.IdP.Identity.Domain.Interfaces;
using Antrapol.IdP.Identity.Domain.ValueObjects;
using Antrapol.IdP.SharedKernel.Handlers;
using Antrapol.IdP.SharedKernel.Results;

namespace Antrapol.IdP.Identity.Application.Commands;

public sealed class RegisterUserCommandHandler : ICommandHandler<RegisterUserCommand, UserDto>
{
    private readonly IUserRepository _userRepository;

    public RegisterUserCommandHandler(IUserRepository userRepository)
    {
        _userRepository = userRepository;
    }

    public async Task<Result<UserDto>> HandleAsync(RegisterUserCommand command, CancellationToken ct = default)
    {
        // Validate email format
        if (!Email.TryCreate(command.Email, out var email) || email is null)
        {
            return Error.Validation("User.InvalidEmail", "Invalid email format.");
        }

        // Check if user already exists
        if (await _userRepository.ExistsAsync(email, ct))
        {
            return Error.Conflict("User.EmailExists", "A user with this email already exists.");
        }

        // Create user
        var user = User.Create(email, command.DisplayName);

        // Persist
        await _userRepository.CreateAsync(user, ct);

        // Return DTO
        return new UserDto(
            user.Id,
            user.Email.Value,
            user.PhoneNumber?.Value,
            user.DisplayName,
            user.Status,
            user.EmailVerified,
            user.PhoneVerified,
            user.LastLoginAt,
            user.CreatedAt);
    }
}
