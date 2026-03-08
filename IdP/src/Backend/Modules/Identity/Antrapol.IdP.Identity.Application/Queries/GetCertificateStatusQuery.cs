namespace Antrapol.IdP.Identity.Application.Queries;

/// <summary>
/// Query to get certificate issuance status for a registration.
/// </summary>
public sealed record GetCertificateStatusQuery(Guid TrackingId);
