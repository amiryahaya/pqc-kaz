using Antrapol.IdP.Identity.Application.DTOs;
using Antrapol.IdP.Identity.Domain.Interfaces;
using Antrapol.IdP.SharedKernel.Handlers;
using Antrapol.IdP.SharedKernel.Results;

namespace Antrapol.IdP.Identity.Application.Queries;

public sealed class GetUserByIdQueryHandler : IQueryHandler<GetUserByIdQuery, UserDto>
{
    private readonly IUserRepository _userRepository;

    public GetUserByIdQueryHandler(IUserRepository userRepository)
    {
        _userRepository = userRepository;
    }

    public async Task<Result<UserDto>> HandleAsync(GetUserByIdQuery query, CancellationToken ct = default)
    {
        var user = await _userRepository.GetByIdAsync(query.UserId, ct);

        if (user is null)
        {
            return Error.NotFound("User.NotFound", $"User with ID '{query.UserId}' was not found.");
        }

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
