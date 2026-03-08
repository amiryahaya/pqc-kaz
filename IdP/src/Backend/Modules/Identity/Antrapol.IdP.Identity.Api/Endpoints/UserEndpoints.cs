using Carter;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Antrapol.IdP.Common.Extensions;
using Antrapol.IdP.Identity.Application.Commands;
using Antrapol.IdP.Identity.Application.Queries;
using Antrapol.IdP.SharedKernel.Handlers;

namespace Antrapol.IdP.Identity.Api.Endpoints;

public sealed class UserEndpoints : ICarterModule
{
    public void AddRoutes(IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/v1/users")
            .WithTags("Users");

        group.MapPost("/", RegisterUser)
            .WithName("RegisterUser")
            .WithSummary("Register a new user")
            .Produces(StatusCodes.Status201Created)
            .ProducesValidationProblem()
            .ProducesProblem(StatusCodes.Status409Conflict);

        group.MapGet("/{id:guid}", GetUserById)
            .WithName("GetUserById")
            .WithSummary("Get user by ID")
            .Produces(StatusCodes.Status200OK)
            .ProducesProblem(StatusCodes.Status404NotFound);
    }

    private static async Task<IResult> RegisterUser(
        RegisterUserRequest request,
        ICommandHandler<RegisterUserCommand, Application.DTOs.UserDto> handler,
        CancellationToken ct)
    {
        var command = new RegisterUserCommand(request.Email, request.DisplayName);
        var result = await handler.HandleAsync(command, ct);

        return result.ToProblemResult(user =>
            Results.Created($"/api/v1/users/{user.Id}", user));
    }

    private static async Task<IResult> GetUserById(
        Guid id,
        IQueryHandler<GetUserByIdQuery, Application.DTOs.UserDto> handler,
        CancellationToken ct)
    {
        var query = new GetUserByIdQuery(id);
        var result = await handler.HandleAsync(query, ct);

        return result.ToProblemResult();
    }
}

public sealed record RegisterUserRequest(string Email, string? DisplayName);
