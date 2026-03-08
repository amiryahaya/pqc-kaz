using System.Security.Cryptography;
using System.Text;
using Antrapol.IdP.Certificate.Application.Interfaces;
using Antrapol.IdP.Certificate.Domain.Enums;
using Antrapol.IdP.Certificate.Domain.Interfaces;
using Antrapol.IdP.Crypto.Domain.Enums;
using Antrapol.IdP.Crypto.Domain.Interfaces;
using Antrapol.IdP.SharedKernel.Results;

namespace Antrapol.IdP.Certificate.Infrastructure.Services;

/// <summary>
/// Service for issuing X.509 certificates using KAZ-SIGN.
/// Implements certificate creation from CSRs with CA signature.
/// Supports all KAZ-SIGN security levels (128, 192, 256).
/// </summary>
public sealed class CertificateIssuanceService : ICertificateIssuanceService
{
    // KAZ-SIGN OIDs for each security level
    private static readonly byte[] KazSign128OidEncoded = [0x06, 0x0A, 0x60, 0x86, 0x83, 0x4A, 0x01, 0x01, 0x01, 0x01, 0x01, 0x80, 0x00];
    private static readonly byte[] KazSign192OidEncoded = [0x06, 0x0A, 0x60, 0x86, 0x83, 0x4A, 0x01, 0x01, 0x01, 0x01, 0x01, 0xC0, 0x00];
    private static readonly byte[] KazSign256OidEncoded = [0x06, 0x09, 0x60, 0x86, 0x83, 0x4A, 0x01, 0x01, 0x01, 0x01, 0x01];

    private readonly ICsrParser _csrParser;
    private readonly ICertificateRepository _certificateRepository;
    private readonly ICryptoProvider _cryptoProvider;
    private readonly ICaKeyProvider _caKeyProvider;

    public CertificateIssuanceService(
        ICsrParser csrParser,
        ICertificateRepository certificateRepository,
        ICryptoProvider cryptoProvider,
        ICaKeyProvider caKeyProvider)
    {
        _csrParser = csrParser;
        _certificateRepository = certificateRepository;
        _cryptoProvider = cryptoProvider;
        _caKeyProvider = caKeyProvider;
    }

    public async Task<Result<IssuedCertificateDto>> IssueCertificateAsync(
        CertificateIssuanceRequest request,
        CancellationToken ct = default)
    {
        // Validate CSR
        var validationResult = await _csrParser.ValidateAsync(request.CsrDer, ct);
        if (validationResult.IsFailure)
        {
            return Error.Validation("Certificate.InvalidCsr", validationResult.Error.Message);
        }

        var csrValidation = validationResult.Value;
        if (!csrValidation.IsValid)
        {
            return Error.Validation("Certificate.InvalidCsr", csrValidation.ValidationError ?? "CSR validation failed");
        }

        // Generate serial number
        var serialNumber = GenerateSerialNumber();

        // Calculate validity period
        var notBefore = DateTimeOffset.UtcNow;
        var notAfter = notBefore.Add(request.ValidityPeriod);

        // Get CA keys
        var (caPublicKey, caSecretKey, issuerDn) = await _caKeyProvider.GetCaKeysAsync(ct);

        // Determine signature algorithm based on CA key size
        var signatureAlgorithm = DetermineSignatureAlgorithm(caSecretKey);

        // Build certificate
        var certificateDer = BuildCertificate(
            serialNumber: serialNumber,
            subjectDn: csrValidation.SubjectDn,
            issuerDn: issuerDn,
            subjectPublicKey: csrValidation.PublicKey,
            notBefore: notBefore,
            notAfter: notAfter,
            caSecretKey: caSecretKey,
            certificateType: request.CertificateType,
            signatureAlgorithm: signatureAlgorithm);

        // Convert to PEM
        var certificatePem = ConvertToPem(certificateDer, "CERTIFICATE");

        // Compute thumbprint (SHA-256 of DER)
        var thumbprint = ComputeThumbprint(certificateDer);

        // Store certificate in database
        var certificate = Domain.Entities.Certificate.Create(
            serialNumber: serialNumber,
            subjectDn: csrValidation.SubjectDn,
            issuerDn: issuerDn,
            issuerId: null, // Could be CA certificate ID if tracked
            type: request.CertificateType,
            algorithm: SignatureAlgorithm.KazSign256,
            publicKey: csrValidation.PublicKey,
            certificateData: certificateDer,
            thumbprint: thumbprint,
            notBefore: notBefore,
            notAfter: notAfter,
            userId: request.UserId);

        var certificateId = await _certificateRepository.CreateAsync(certificate, ct);

        return new IssuedCertificateDto(
            CertificateId: certificateId,
            SerialNumber: serialNumber,
            CertificateDer: certificateDer,
            CertificatePem: certificatePem,
            SubjectDn: csrValidation.SubjectDn,
            IssuerDn: issuerDn,
            NotBefore: notBefore,
            NotAfter: notAfter,
            PublicKeyFingerprint: csrValidation.PublicKeyFingerprint);
    }

    public async Task<Result<CsrValidationResult>> ValidateCsrAsync(byte[] csrDer, CancellationToken ct = default)
    {
        return await _csrParser.ValidateAsync(csrDer, ct);
    }

    public Task<Result<bool>> VerifyCertificateChainAsync(byte[] certificateDer, CancellationToken ct = default)
    {
        // TODO: Implement certificate chain verification
        return Task.FromResult<Result<bool>>(true);
    }

    private byte[] BuildCertificate(
        string serialNumber,
        string subjectDn,
        string issuerDn,
        byte[] subjectPublicKey,
        DateTimeOffset notBefore,
        DateTimeOffset notAfter,
        byte[] caSecretKey,
        CertificateType certificateType,
        KeyAlgorithm signatureAlgorithm = KeyAlgorithm.KazSign256)
    {
        // Build TBSCertificate
        var tbsCertificate = BuildTbsCertificate(
            serialNumber, subjectDn, issuerDn, subjectPublicKey,
            notBefore, notAfter, certificateType, signatureAlgorithm);

        // Sign TBSCertificate with CA key using the appropriate algorithm
        var signature = _cryptoProvider.SignAsync(tbsCertificate, caSecretKey, signatureAlgorithm)
            .GetAwaiter().GetResult();

        // Assemble final certificate
        return AssembleCertificate(tbsCertificate, signature, signatureAlgorithm);
    }

    /// <summary>
    /// Determines the signature algorithm based on CA secret key size.
    /// </summary>
    private static KeyAlgorithm DetermineSignatureAlgorithm(byte[] caSecretKey) => caSecretKey.Length switch
    {
        32 => KeyAlgorithm.KazSign128,   // Level 128 secret key
        50 => KeyAlgorithm.KazSign192,   // Level 192 secret key
        64 => KeyAlgorithm.KazSign256,   // Level 256 secret key
        _ => KeyAlgorithm.KazSign256     // Default to 256
    };

    /// <summary>
    /// Gets the encoded OID for the specified algorithm.
    /// </summary>
    private static byte[] GetAlgorithmOidEncoded(KeyAlgorithm algorithm) => algorithm switch
    {
        KeyAlgorithm.KazSign128 => KazSign128OidEncoded,
        KeyAlgorithm.KazSign192 => KazSign192OidEncoded,
        KeyAlgorithm.KazSign256 => KazSign256OidEncoded,
        _ => KazSign256OidEncoded
    };

    private static byte[] BuildTbsCertificate(
        string serialNumber,
        string subjectDn,
        string issuerDn,
        byte[] subjectPublicKey,
        DateTimeOffset notBefore,
        DateTimeOffset notAfter,
        CertificateType certificateType,
        KeyAlgorithm signatureAlgorithm = KeyAlgorithm.KazSign256)
    {
        var builder = new DerBuilder();

        builder.BeginSequence(); // TBSCertificate

        // Version [0] EXPLICIT INTEGER (v3 = 2)
        builder.WriteContextTag(0, BuildInteger(2));

        // SerialNumber INTEGER
        builder.WriteInteger(serialNumber);

        // Signature AlgorithmIdentifier
        builder.WriteRaw(BuildAlgorithmIdentifier(signatureAlgorithm));

        // Issuer Name
        builder.WriteRaw(BuildName(issuerDn));

        // Validity
        builder.BeginSequence();
        builder.WriteUtcTime(notBefore);
        builder.WriteUtcTime(notAfter);
        builder.EndSequence();

        // Subject Name
        builder.WriteRaw(BuildName(subjectDn));

        // SubjectPublicKeyInfo
        builder.WriteRaw(BuildSubjectPublicKeyInfo(subjectPublicKey));

        // Extensions [3] OPTIONAL
        var extensions = BuildExtensions(certificateType);
        builder.WriteContextTag(3, extensions);

        builder.EndSequence();

        return builder.Build();
    }

    private static byte[] AssembleCertificate(
        byte[] tbsCertificate,
        byte[] signature,
        KeyAlgorithm signatureAlgorithm = KeyAlgorithm.KazSign256)
    {
        var builder = new DerBuilder();

        builder.BeginSequence(); // Certificate

        // TBSCertificate (already DER encoded)
        builder.WriteRaw(tbsCertificate);

        // SignatureAlgorithm
        builder.WriteRaw(BuildAlgorithmIdentifier(signatureAlgorithm));

        // SignatureValue BIT STRING
        builder.WriteBitString(signature);

        builder.EndSequence();

        return builder.Build();
    }

    private static byte[] BuildAlgorithmIdentifier(KeyAlgorithm algorithm = KeyAlgorithm.KazSign256)
    {
        var builder = new DerBuilder();
        builder.BeginSequence();
        builder.WriteRaw(GetAlgorithmOidEncoded(algorithm));
        builder.EndSequence();
        return builder.Build();
    }

    private static byte[] BuildSubjectPublicKeyInfo(byte[] publicKey)
    {
        var builder = new DerBuilder();
        builder.BeginSequence();
        builder.WriteRaw(BuildAlgorithmIdentifier());
        builder.WriteBitString(publicKey);
        builder.EndSequence();
        return builder.Build();
    }

    private static byte[] BuildName(string dn)
    {
        // Parse DN and build X.500 Name
        var builder = new DerBuilder();
        builder.BeginSequence();

        // Parse DN components like "CN=Name, O=Org, C=MY"
        var parts = ParseDn(dn);
        foreach (var (oid, value) in parts)
        {
            builder.WriteRaw(BuildRdn(oid, value));
        }

        builder.EndSequence();
        return builder.Build();
    }

    private static List<(byte[] oid, string value)> ParseDn(string dn)
    {
        var result = new List<(byte[] oid, string value)>();
        var parts = dn.Split(',', StringSplitOptions.TrimEntries);

        foreach (var part in parts)
        {
            var kv = part.Split('=', 2);
            if (kv.Length != 2) continue;

            var key = kv[0].Trim().ToUpperInvariant();
            var value = kv[1].Trim();

            byte[] oid = key switch
            {
                "C" => [0x55, 0x04, 0x06],
                "O" => [0x55, 0x04, 0x0A],
                "OU" => [0x55, 0x04, 0x0B],
                "CN" => [0x55, 0x04, 0x03],
                "SERIALNUMBER" => [0x55, 0x04, 0x05],
                "EMAIL" or "EMAILADDRESS" => [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x01],
                _ => []
            };

            if (oid.Length > 0)
            {
                result.Add((oid, value));
            }
        }

        return result;
    }

    private static byte[] BuildRdn(byte[] oid, string value)
    {
        var builder = new DerBuilder();
        builder.BeginSet();
        builder.BeginSequence();
        builder.WriteOid(oid);
        builder.WriteUtf8String(value);
        builder.EndSequence();
        builder.EndSet();
        return builder.Build();
    }

    private static byte[] BuildInteger(int value)
    {
        var builder = new DerBuilder();
        builder.WriteInteger(value);
        return builder.Build();
    }

    private static byte[] BuildExtensions(CertificateType certificateType)
    {
        var builder = new DerBuilder();
        builder.BeginSequence(); // Extensions

        // Basic Constraints
        builder.WriteRaw(BuildBasicConstraintsExtension(
            isCa: certificateType is CertificateType.RootCa or CertificateType.IntermediateCa));

        // Key Usage
        builder.WriteRaw(BuildKeyUsageExtension(certificateType));

        builder.EndSequence();
        return builder.Build();
    }

    private static byte[] BuildBasicConstraintsExtension(bool isCa)
    {
        var builder = new DerBuilder();
        builder.BeginSequence(); // Extension

        // OID: 2.5.29.19 (basicConstraints)
        builder.WriteOid([0x55, 0x1D, 0x13]);

        // Critical
        builder.WriteBoolean(true);

        // Value (OCTET STRING containing SEQUENCE)
        var value = new DerBuilder();
        value.BeginSequence();
        value.WriteBoolean(isCa);
        value.EndSequence();
        builder.WriteOctetString(value.Build());

        builder.EndSequence();
        return builder.Build();
    }

    private static byte[] BuildKeyUsageExtension(CertificateType certificateType)
    {
        var builder = new DerBuilder();
        builder.BeginSequence(); // Extension

        // OID: 2.5.29.15 (keyUsage)
        builder.WriteOid([0x55, 0x1D, 0x0F]);

        // Critical
        builder.WriteBoolean(true);

        // Key usage bits
        byte keyUsage = certificateType switch
        {
            CertificateType.RootCa or CertificateType.IntermediateCa => 0x06, // keyCertSign, cRLSign
            CertificateType.EndEntitySigning => 0x80, // digitalSignature
            CertificateType.EndEntityEncryption => 0x28, // keyEncipherment, dataEncipherment
            _ => 0x80
        };

        var value = new DerBuilder();
        value.WriteBitString([keyUsage]);
        builder.WriteOctetString(value.Build());

        builder.EndSequence();
        return builder.Build();
    }

    private static string GenerateSerialNumber()
    {
        var bytes = new byte[16];
        RandomNumberGenerator.Fill(bytes);
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    private static string ComputeThumbprint(byte[] certificateDer)
    {
        var hash = SHA256.HashData(certificateDer);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static string ConvertToPem(byte[] der, string label)
    {
        var base64 = Convert.ToBase64String(der);
        var sb = new StringBuilder();
        sb.Append("-----BEGIN ").Append(label).AppendLine("-----");

        for (var i = 0; i < base64.Length; i += 64)
        {
            var length = Math.Min(64, base64.Length - i);
            sb.AppendLine(base64.Substring(i, length));
        }

        sb.Append("-----END ").Append(label).AppendLine("-----");
        return sb.ToString();
    }
}

/// <summary>
/// Interface for providing CA key material.
/// </summary>
public interface ICaKeyProvider
{
    Task<(byte[] PublicKey, byte[] SecretKey, string IssuerDn)> GetCaKeysAsync(CancellationToken ct = default);
}

/// <summary>
/// Simple DER builder for constructing ASN.1 structures.
/// </summary>
internal sealed class DerBuilder
{
    private readonly List<byte> _data = [];
    private readonly Stack<int> _sequenceStarts = new();

    public void BeginSequence()
    {
        _data.Add(0x30);
        _sequenceStarts.Push(_data.Count);
        _data.Add(0x00); // Placeholder for length
    }

    public void EndSequence()
    {
        FinalizeContainer();
    }

    public void BeginSet()
    {
        _data.Add(0x31);
        _sequenceStarts.Push(_data.Count);
        _data.Add(0x00);
    }

    public void EndSet()
    {
        FinalizeContainer();
    }

    public void WriteInteger(int value)
    {
        _data.Add(0x02);
        if (value == 0)
        {
            _data.Add(0x01);
            _data.Add(0x00);
        }
        else
        {
            var bytes = BitConverter.GetBytes(value);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(bytes);

            // Remove leading zeros
            var start = 0;
            while (start < bytes.Length - 1 && bytes[start] == 0 && (bytes[start + 1] & 0x80) == 0)
                start++;

            // Add leading zero if high bit set
            if ((bytes[start] & 0x80) != 0)
            {
                WriteLength(bytes.Length - start + 1);
                _data.Add(0x00);
            }
            else
            {
                WriteLength(bytes.Length - start);
            }

            for (var i = start; i < bytes.Length; i++)
                _data.Add(bytes[i]);
        }
    }

    public void WriteInteger(string hexValue)
    {
        var bytes = Convert.FromHexString(hexValue);
        _data.Add(0x02);
        if ((bytes[0] & 0x80) != 0)
        {
            WriteLength(bytes.Length + 1);
            _data.Add(0x00);
        }
        else
        {
            WriteLength(bytes.Length);
        }
        _data.AddRange(bytes);
    }

    public void WriteOid(byte[] oid)
    {
        _data.Add(0x06);
        WriteLength(oid.Length);
        _data.AddRange(oid);
    }

    public void WriteUtf8String(string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        _data.Add(0x0C);
        WriteLength(bytes.Length);
        _data.AddRange(bytes);
    }

    public void WriteBoolean(bool value)
    {
        _data.Add(0x01);
        _data.Add(0x01);
        _data.Add(value ? (byte)0xFF : (byte)0x00);
    }

    public void WriteBitString(byte[] content)
    {
        _data.Add(0x03);
        WriteLength(content.Length + 1);
        _data.Add(0x00); // No unused bits
        _data.AddRange(content);
    }

    public void WriteOctetString(byte[] content)
    {
        _data.Add(0x04);
        WriteLength(content.Length);
        _data.AddRange(content);
    }

    public void WriteUtcTime(DateTimeOffset time)
    {
        var utcTime = time.UtcDateTime.ToString("yyMMddHHmmss", System.Globalization.CultureInfo.InvariantCulture) + "Z";
        var bytes = Encoding.ASCII.GetBytes(utcTime);
        _data.Add(0x17); // UTCTime tag
        WriteLength(bytes.Length);
        _data.AddRange(bytes);
    }

    public void WriteContextTag(int tag, byte[] content)
    {
        _data.Add((byte)(0xA0 | tag));
        WriteLength(content.Length);
        _data.AddRange(content);
    }

    public void WriteRaw(byte[] data)
    {
        _data.AddRange(data);
    }

    public byte[] Build()
    {
        return [.. _data];
    }

    private void WriteLength(int length)
    {
        if (length < 128)
        {
            _data.Add((byte)length);
        }
        else if (length < 256)
        {
            _data.Add(0x81);
            _data.Add((byte)length);
        }
        else if (length < 65536)
        {
            _data.Add(0x82);
            _data.Add((byte)(length >> 8));
            _data.Add((byte)(length & 0xFF));
        }
        else
        {
            _data.Add(0x83);
            _data.Add((byte)(length >> 16));
            _data.Add((byte)((length >> 8) & 0xFF));
            _data.Add((byte)(length & 0xFF));
        }
    }

    private void FinalizeContainer()
    {
        if (_sequenceStarts.Count == 0)
            return;

        var startIndex = _sequenceStarts.Pop();
        var contentLength = _data.Count - startIndex - 1;

        // Replace placeholder with actual length
        if (contentLength < 128)
        {
            _data[startIndex] = (byte)contentLength;
        }
        else
        {
            // Need to expand for multi-byte length
            var prefix = _data.Take(startIndex).ToList();
            var content = _data.Skip(startIndex + 1).ToList();

            _data.Clear();
            _data.AddRange(prefix);
            WriteLength(contentLength);
            _data.AddRange(content);
        }
    }
}
