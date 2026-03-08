using Carter;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Antrapol.IdP.Common.Extensions;
using Antrapol.IdP.Identity.Application.Commands;
using Antrapol.IdP.Identity.Application.DTOs;
using Antrapol.IdP.Identity.Application.Queries;
using Antrapol.IdP.Identity.Domain.Enums;
using Antrapol.IdP.SharedKernel.Handlers;

namespace Antrapol.IdP.Identity.Api.Endpoints;

public sealed class RegistrationEndpoints : ICarterModule
{
    public void AddRoutes(IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/v1/identity/registration")
            .WithTags("Registration");

        // Step 1: Initiate registration with full profile
        group.MapPost("/initiate", InitiateRegistration)
            .WithName("InitiateRegistration")
            .WithSummary("Initiate user registration with profile and send email OTP")
            .WithDescription("Collects user profile (name, MyKad, email, phone) and sends email OTP for verification.")
            .Produces<InitiateRegistrationDto>(StatusCodes.Status200OK)
            .ProducesValidationProblem()
            .ProducesProblem(StatusCodes.Status409Conflict);

        // Step 2: Verify email OTP
        group.MapPost("/{id:guid}/verify-email", VerifyEmailOtp)
            .WithName("VerifyEmailOtp")
            .WithSummary("Verify email with OTP")
            .Produces<VerifyEmailOtpDto>(StatusCodes.Status200OK)
            .ProducesValidationProblem()
            .ProducesProblem(StatusCodes.Status404NotFound);

        // Step 3: Send phone OTP (after email verified)
        group.MapPost("/{id:guid}/send-phone-otp", SendPhoneOtp)
            .WithName("SendPhoneOtp")
            .WithSummary("Send phone OTP after email verification")
            .Produces<SendPhoneOtpDto>(StatusCodes.Status200OK)
            .ProducesValidationProblem()
            .ProducesProblem(StatusCodes.Status404NotFound);

        // Step 4: Verify phone OTP
        group.MapPost("/{id:guid}/verify-phone", VerifyPhoneOtp)
            .WithName("VerifyPhoneOtp")
            .WithSummary("Verify phone with OTP")
            .Produces<VerifyPhoneOtpDto>(StatusCodes.Status200OK)
            .ProducesValidationProblem()
            .ProducesProblem(StatusCodes.Status404NotFound);

        // Step 5: Submit CSR (after phone verified)
        group.MapPost("/{id:guid}/submit-csr", SubmitCsr)
            .WithName("SubmitCsr")
            .WithSummary("Submit device and user CSRs with encrypted key shares")
            .WithDescription("Submits CSRs for certificate issuance. Includes encrypted key shares for secret sharing.")
            .Produces<SubmitCsrDto>(StatusCodes.Status200OK)
            .ProducesValidationProblem()
            .ProducesProblem(StatusCodes.Status404NotFound)
            .ProducesProblem(StatusCodes.Status409Conflict);

        // Step 6: Poll for certificate status
        group.MapGet("/{trackingId:guid}/certificates", GetCertificateStatus)
            .WithName("GetCertificateStatus")
            .WithSummary("Get certificate issuance status and download certificates")
            .Produces<CertificateStatusDto>(StatusCodes.Status200OK)
            .ProducesProblem(StatusCodes.Status404NotFound);

        // Step 7: Complete registration (activate identity)
        group.MapPost("/{id:guid}/complete", CompleteRegistration)
            .WithName("CompleteRegistration")
            .WithSummary("Complete registration and activate identity")
            .Produces<CompleteRegistrationDto>(StatusCodes.Status201Created)
            .ProducesValidationProblem()
            .ProducesProblem(StatusCodes.Status404NotFound)
            .ProducesProblem(StatusCodes.Status409Conflict);

        // Status endpoint
        group.MapGet("/{trackingId:guid}/status", GetRegistrationStatus)
            .WithName("GetRegistrationStatus")
            .WithSummary("Get registration status by tracking ID")
            .Produces<RegistrationStatusDto>(StatusCodes.Status200OK)
            .ProducesProblem(StatusCodes.Status404NotFound);
    }

    private static async Task<IResult> InitiateRegistration(
        InitiateRegistrationRequest request,
        ICommandHandler<InitiateRegistrationCommand, InitiateRegistrationDto> handler,
        CancellationToken ct)
    {
        var command = new InitiateRegistrationCommand(
            FullName: request.FullName,
            MyKadNumber: request.MyKadNumber,
            Email: request.Email,
            PhoneNumber: request.PhoneNumber,
            DeviceId: request.DeviceId,
            DeviceName: request.DeviceName,
            DevicePlatform: request.DevicePlatform,
            DeviceOsVersion: request.DeviceOsVersion,
            AppVersion: request.AppVersion);

        var result = await handler.HandleAsync(command, ct);
        return result.ToProblemResult();
    }

    private static async Task<IResult> VerifyEmailOtp(
        Guid id,
        VerifyOtpRequest request,
        ICommandHandler<VerifyEmailOtpCommand, VerifyEmailOtpDto> handler,
        CancellationToken ct)
    {
        var command = new VerifyEmailOtpCommand(id, request.Otp);
        var result = await handler.HandleAsync(command, ct);
        return result.ToProblemResult();
    }

    private static async Task<IResult> SendPhoneOtp(
        Guid id,
        ICommandHandler<SendPhoneOtpCommand, SendPhoneOtpDto> handler,
        CancellationToken ct)
    {
        var command = new SendPhoneOtpCommand(id);
        var result = await handler.HandleAsync(command, ct);
        return result.ToProblemResult();
    }

    private static async Task<IResult> VerifyPhoneOtp(
        Guid id,
        VerifyOtpRequest request,
        ICommandHandler<VerifyPhoneOtpCommand, VerifyPhoneOtpDto> handler,
        CancellationToken ct)
    {
        var command = new VerifyPhoneOtpCommand(id, request.Otp);
        var result = await handler.HandleAsync(command, ct);
        return result.ToProblemResult();
    }

    private static async Task<IResult> SubmitCsr(
        Guid id,
        SubmitCsrRequest request,
        ICommandHandler<SubmitCsrCommand, SubmitCsrDto> handler,
        CancellationToken ct)
    {
        var command = new SubmitCsrCommand(
            RegistrationId: id,
            DeviceCsr: request.DeviceCsr,
            UserCsr: request.UserCsr,
            EncryptedPartControl: new EncryptedShareDto(
                request.EncryptedPartControl.Ciphertext,
                request.EncryptedPartControl.EncapsulatedKey,
                request.EncryptedPartControl.Nonce,
                request.EncryptedPartControl.AuthTag,
                request.EncryptedPartControl.Salt),
            EncryptedPartRecovery: new EncryptedShareDto(
                request.EncryptedPartRecovery.Ciphertext,
                request.EncryptedPartRecovery.EncapsulatedKey,
                request.EncryptedPartRecovery.Nonce,
                request.EncryptedPartRecovery.AuthTag,
                request.EncryptedPartRecovery.Salt),
            PayloadSignature: request.PayloadSignature);

        var result = await handler.HandleAsync(command, ct);
        return result.ToProblemResult();
    }

    private static async Task<IResult> GetCertificateStatus(
        Guid trackingId,
        IQueryHandler<GetCertificateStatusQuery, CertificateStatusDto> handler,
        CancellationToken ct)
    {
        var query = new GetCertificateStatusQuery(trackingId);
        var result = await handler.HandleAsync(query, ct);
        return result.ToProblemResult();
    }

    private static async Task<IResult> CompleteRegistration(
        Guid id,
        ICommandHandler<CompleteRegistrationCommand, CompleteRegistrationDto> handler,
        CancellationToken ct)
    {
        var command = new CompleteRegistrationCommand(id);
        var result = await handler.HandleAsync(command, ct);
        return result.ToProblemResult(dto =>
            Results.Created($"/api/v1/users/{dto.UserId}", dto));
    }

    private static async Task<IResult> GetRegistrationStatus(
        Guid trackingId,
        IQueryHandler<GetRegistrationStatusQuery, RegistrationStatusDto> handler,
        CancellationToken ct)
    {
        var query = new GetRegistrationStatusQuery(trackingId);
        var result = await handler.HandleAsync(query, ct);
        return result.ToProblemResult();
    }
}

// === Request DTOs ===

public sealed record InitiateRegistrationRequest(
    string FullName,
    string MyKadNumber,
    string Email,
    string PhoneNumber,
    string? DeviceId = null,
    string? DeviceName = null,
    DevicePlatform? DevicePlatform = null,
    string? DeviceOsVersion = null,
    string? AppVersion = null);

public sealed record VerifyOtpRequest(string Otp);

public sealed record SubmitCsrRequest(
    string DeviceCsr,           // Base64 encoded DER
    string UserCsr,             // Base64 encoded DER
    EncryptedShareRequest EncryptedPartControl,
    EncryptedShareRequest EncryptedPartRecovery,
    string PayloadSignature);   // Base64 encoded signature

public sealed record EncryptedShareRequest(
    string Ciphertext,
    string? EncapsulatedKey,
    string? Nonce,
    string? AuthTag,
    string? Salt);
