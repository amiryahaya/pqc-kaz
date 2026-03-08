using Microsoft.AspNetCore.Http;
using Antrapol.IdP.SharedKernel.Results;

namespace Antrapol.IdP.Common.Extensions;

/// <summary>
/// Extension methods for converting Result types to HTTP responses using ProblemDetails.
/// </summary>
public static class ResultExtensions
{
    /// <summary>
    /// Converts a Result to an appropriate IResult for minimal API responses.
    /// </summary>
    public static IResult ToProblemResult(this Result result)
    {
        if (result.IsSuccess)
        {
            return Results.Ok();
        }

        return result.Error.ToProblemResult();
    }

    /// <summary>
    /// Converts a Result&lt;T&gt; to an appropriate IResult for minimal API responses.
    /// </summary>
    public static IResult ToProblemResult<T>(this Result<T> result)
    {
        if (result.IsSuccess)
        {
            return Results.Ok(result.Value);
        }

        return result.Error.ToProblemResult();
    }

    /// <summary>
    /// Converts a Result&lt;T&gt; to an appropriate IResult with a custom success result factory.
    /// </summary>
    public static IResult ToProblemResult<T>(this Result<T> result, Func<T, IResult> onSuccess)
    {
        if (result.IsSuccess)
        {
            return onSuccess(result.Value);
        }

        return result.Error.ToProblemResult();
    }

    /// <summary>
    /// Converts a ValidationResult to an appropriate IResult with validation problem details.
    /// </summary>
    public static IResult ToProblemResult(this ValidationResult result)
    {
        if (result.IsSuccess)
        {
            return Results.Ok();
        }

        var errors = result.Errors
            .GroupBy(e => e.Code)
            .ToDictionary(
                g => g.Key,
                g => g.Select(e => e.Message).ToArray());

        return Results.ValidationProblem(
            errors,
            title: "Validation Failed",
            type: "https://tools.ietf.org/html/rfc9110#section-15.5.1");
    }

    /// <summary>
    /// Converts a ValidationResult&lt;T&gt; to an appropriate IResult with validation problem details.
    /// </summary>
    public static IResult ToProblemResult<T>(this ValidationResult<T> result)
    {
        if (result.IsSuccess)
        {
            return Results.Ok(result.Value);
        }

        var errors = result.Errors
            .GroupBy(e => e.Code)
            .ToDictionary(
                g => g.Key,
                g => g.Select(e => e.Message).ToArray());

        return Results.ValidationProblem(
            errors,
            title: "Validation Failed",
            type: "https://tools.ietf.org/html/rfc9110#section-15.5.1");
    }

    /// <summary>
    /// Converts an Error to an appropriate IResult using ProblemDetails.
    /// </summary>
    public static IResult ToProblemResult(this Error error)
    {
        return error.Type switch
        {
            ErrorType.Validation => Results.Problem(
                statusCode: StatusCodes.Status400BadRequest,
                title: "Bad Request",
                detail: error.Message,
                type: "https://tools.ietf.org/html/rfc9110#section-15.5.1",
                extensions: new Dictionary<string, object?> { ["code"] = error.Code }),

            ErrorType.NotFound => Results.Problem(
                statusCode: StatusCodes.Status404NotFound,
                title: "Not Found",
                detail: error.Message,
                type: "https://tools.ietf.org/html/rfc9110#section-15.5.5",
                extensions: new Dictionary<string, object?> { ["code"] = error.Code }),

            ErrorType.Conflict => Results.Problem(
                statusCode: StatusCodes.Status409Conflict,
                title: "Conflict",
                detail: error.Message,
                type: "https://tools.ietf.org/html/rfc9110#section-15.5.10",
                extensions: new Dictionary<string, object?> { ["code"] = error.Code }),

            ErrorType.Unauthorized => Results.Problem(
                statusCode: StatusCodes.Status401Unauthorized,
                title: "Unauthorized",
                detail: error.Message,
                type: "https://tools.ietf.org/html/rfc9110#section-15.5.2",
                extensions: new Dictionary<string, object?> { ["code"] = error.Code }),

            ErrorType.Forbidden => Results.Problem(
                statusCode: StatusCodes.Status403Forbidden,
                title: "Forbidden",
                detail: error.Message,
                type: "https://tools.ietf.org/html/rfc9110#section-15.5.4",
                extensions: new Dictionary<string, object?> { ["code"] = error.Code }),

            _ => Results.Problem(
                statusCode: StatusCodes.Status500InternalServerError,
                title: "Internal Server Error",
                detail: error.Message,
                type: "https://tools.ietf.org/html/rfc9110#section-15.6.1",
                extensions: new Dictionary<string, object?> { ["code"] = error.Code })
        };
    }
}
