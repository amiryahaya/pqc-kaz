using System.Security.Cryptography;
using System.Text;
using Antrapol.IdP.Certificate.Application.Interfaces;
using Antrapol.IdP.Certificate.Domain.Enums;
using Antrapol.IdP.Crypto.Infrastructure.Providers;
using Antrapol.IdP.SharedKernel.Results;

namespace Antrapol.IdP.Certificate.Infrastructure.Services;

/// <summary>
/// Service for parsing PKCS#10 Certificate Signing Requests (CSRs).
/// Implements ASN.1/DER parsing with KAZ-SIGN-256 signature verification.
/// </summary>
public sealed class CsrParserService : ICsrParser
{
    // KAZ-SIGN-256 OID: 2.16.458.1.1.1.1.1
    private static readonly byte[] KazSign256OidBytes = [0x60, 0x86, 0x83, 0x4A, 0x01, 0x01, 0x01, 0x01, 0x01];
    private const string KazSign256Oid = "2.16.458.1.1.1.1.1";

    // Standard X.500 OIDs
    private const string OidCommonName = "2.5.4.3";
    private const string OidSerialNumber = "2.5.4.5";
    private const string OidCountry = "2.5.4.6";
    private const string OidOrganization = "2.5.4.10";
    private const string OidEmailAddress = "1.2.840.113549.1.9.1";

    private readonly KazSignProvider _kazSignProvider;

    public CsrParserService(KazSignProvider kazSignProvider)
    {
        _kazSignProvider = kazSignProvider;
    }

    public Result<ParsedCsr> Parse(byte[] csrDer)
    {
        try
        {
            var reader = new Asn1Reader(csrDer);

            // CertificationRequest SEQUENCE
            if (!reader.ReadSequence(out var csrContent))
            {
                return Error.Validation("CSR.InvalidFormat", "Invalid CSR: Expected SEQUENCE at root");
            }

            var csrReader = new Asn1Reader(csrContent);

            // CertificationRequestInfo SEQUENCE (TBS data)
            var tbsStart = csrReader.Position;
            if (!csrReader.ReadSequence(out var tbsContent))
            {
                return Error.Validation("CSR.InvalidFormat", "Invalid CSR: Expected CertificationRequestInfo SEQUENCE");
            }
            var tbsEnd = csrReader.Position;
            var tbsData = csrDer[tbsStart..tbsEnd];

            var tbsReader = new Asn1Reader(tbsContent);

            // Version INTEGER (should be 0)
            if (!tbsReader.ReadInteger(out var version))
            {
                return Error.Validation("CSR.InvalidFormat", "Invalid CSR: Expected version INTEGER");
            }

            // Subject Name SEQUENCE
            if (!tbsReader.ReadSequence(out var subjectContent))
            {
                return Error.Validation("CSR.InvalidFormat", "Invalid CSR: Expected subject Name SEQUENCE");
            }
            var subject = ParseSubjectDn(subjectContent);
            var subjectDn = BuildSubjectDnString(subject);

            // SubjectPublicKeyInfo SEQUENCE
            if (!tbsReader.ReadSequence(out var spkiContent))
            {
                return Error.Validation("CSR.InvalidFormat", "Invalid CSR: Expected SubjectPublicKeyInfo SEQUENCE");
            }
            var (publicKey, algorithmOid) = ParseSubjectPublicKeyInfo(spkiContent);

            // SignatureAlgorithm SEQUENCE
            if (!csrReader.ReadSequence(out var sigAlgContent))
            {
                return Error.Validation("CSR.InvalidFormat", "Invalid CSR: Expected signatureAlgorithm SEQUENCE");
            }
            var sigAlgReader = new Asn1Reader(sigAlgContent);
            if (!sigAlgReader.ReadOid(out var signatureAlgorithmOid))
            {
                return Error.Validation("CSR.InvalidFormat", "Invalid CSR: Expected signature algorithm OID");
            }

            // Signature BIT STRING
            if (!csrReader.ReadBitString(out var signature))
            {
                return Error.Validation("CSR.InvalidFormat", "Invalid CSR: Expected signature BIT STRING");
            }

            // Validate algorithm is KAZ-SIGN-256
            var signatureAlgorithm = ParseSignatureAlgorithm(signatureAlgorithmOid);
            if (signatureAlgorithm != SignatureAlgorithm.KazSign256)
            {
                return Error.Validation("CSR.UnsupportedAlgorithm",
                    $"Unsupported signature algorithm: {signatureAlgorithmOid}. Only KAZ-SIGN-256 is supported.");
            }

            // Compute public key fingerprint
            var fingerprint = ComputeFingerprint(publicKey);

            return new ParsedCsr(
                Version: version,
                SubjectDn: subjectDn,
                PublicKey: publicKey,
                PublicKeyFingerprint: fingerprint,
                SignatureAlgorithmOid: signatureAlgorithmOid,
                SignatureAlgorithm: signatureAlgorithm,
                Signature: signature,
                TbsData: tbsData,
                Subject: subject);
        }
        catch (Exception ex)
        {
            return Error.Validation("CSR.ParseError", $"Failed to parse CSR: {ex.Message}");
        }
    }

    public async Task<bool> VerifySignatureAsync(byte[] csrDer, CancellationToken ct = default)
    {
        var parseResult = Parse(csrDer);
        if (parseResult.IsFailure)
        {
            return false;
        }

        var csr = parseResult.Value;

        // Verify using KAZ-SIGN-256
        return await Task.Run(() =>
            _kazSignProvider.Verify(csr.PublicKey, csr.TbsData, csr.Signature), ct);
    }

    public async Task<Result<CsrValidationResult>> ValidateAsync(byte[] csrDer, CancellationToken ct = default)
    {
        // Parse CSR
        var parseResult = Parse(csrDer);
        if (parseResult.IsFailure)
        {
            return new CsrValidationResult(
                IsValid: false,
                SubjectDn: "",
                PublicKey: [],
                PublicKeyFingerprint: "",
                Algorithm: SignatureAlgorithm.KazSign256,
                ValidationError: parseResult.Error.Message);
        }

        var csr = parseResult.Value;

        // Verify signature
        var signatureValid = await VerifySignatureAsync(csrDer, ct);
        if (!signatureValid)
        {
            return new CsrValidationResult(
                IsValid: false,
                SubjectDn: csr.SubjectDn,
                PublicKey: csr.PublicKey,
                PublicKeyFingerprint: csr.PublicKeyFingerprint,
                Algorithm: csr.SignatureAlgorithm,
                ValidationError: "CSR signature verification failed");
        }

        // Validate subject contains required fields
        if (string.IsNullOrEmpty(csr.Subject.CommonName))
        {
            return new CsrValidationResult(
                IsValid: false,
                SubjectDn: csr.SubjectDn,
                PublicKey: csr.PublicKey,
                PublicKeyFingerprint: csr.PublicKeyFingerprint,
                Algorithm: csr.SignatureAlgorithm,
                ValidationError: "CSR subject must contain Common Name (CN)");
        }

        if (string.IsNullOrEmpty(csr.Subject.SerialNumber))
        {
            return new CsrValidationResult(
                IsValid: false,
                SubjectDn: csr.SubjectDn,
                PublicKey: csr.PublicKey,
                PublicKeyFingerprint: csr.PublicKeyFingerprint,
                Algorithm: csr.SignatureAlgorithm,
                ValidationError: "CSR subject must contain Serial Number (MyKad)");
        }

        return new CsrValidationResult(
            IsValid: true,
            SubjectDn: csr.SubjectDn,
            PublicKey: csr.PublicKey,
            PublicKeyFingerprint: csr.PublicKeyFingerprint,
            Algorithm: csr.SignatureAlgorithm);
    }

    private static ParsedSubject ParseSubjectDn(byte[] subjectContent)
    {
        var reader = new Asn1Reader(subjectContent);
        string? commonName = null;
        string? serialNumber = null;
        string? country = null;
        string? organization = null;
        string? emailAddress = null;

        // Subject is a SEQUENCE OF SET OF AttributeTypeAndValue
        while (reader.HasData)
        {
            if (!reader.ReadSet(out var rdnContent))
                break;

            var rdnReader = new Asn1Reader(rdnContent);
            while (rdnReader.HasData)
            {
                if (!rdnReader.ReadSequence(out var atavContent))
                    break;

                var atavReader = new Asn1Reader(atavContent);
                if (!atavReader.ReadOid(out var oid))
                    continue;

                if (!atavReader.ReadString(out var value))
                    continue;

                switch (oid)
                {
                    case OidCommonName:
                        commonName = value;
                        break;
                    case OidSerialNumber:
                        serialNumber = value;
                        break;
                    case OidCountry:
                        country = value;
                        break;
                    case OidOrganization:
                        organization = value;
                        break;
                    case OidEmailAddress:
                        emailAddress = value;
                        break;
                }
            }
        }

        return new ParsedSubject(commonName, serialNumber, country, organization, emailAddress);
    }

    private static string BuildSubjectDnString(ParsedSubject subject)
    {
        var parts = new List<string>();
        if (!string.IsNullOrEmpty(subject.Country))
            parts.Add($"C={subject.Country}");
        if (!string.IsNullOrEmpty(subject.Organization))
            parts.Add($"O={subject.Organization}");
        if (!string.IsNullOrEmpty(subject.CommonName))
            parts.Add($"CN={subject.CommonName}");
        if (!string.IsNullOrEmpty(subject.SerialNumber))
            parts.Add($"SERIALNUMBER={subject.SerialNumber}");
        if (!string.IsNullOrEmpty(subject.EmailAddress))
            parts.Add($"EMAIL={subject.EmailAddress}");

        return string.Join(", ", parts);
    }

    private static (byte[] publicKey, string algorithmOid) ParseSubjectPublicKeyInfo(byte[] spkiContent)
    {
        var reader = new Asn1Reader(spkiContent);

        // Algorithm SEQUENCE
        if (!reader.ReadSequence(out var algContent))
            throw new FormatException("Invalid SubjectPublicKeyInfo: Expected algorithm SEQUENCE");

        var algReader = new Asn1Reader(algContent);
        if (!algReader.ReadOid(out var algorithmOid))
            throw new FormatException("Invalid SubjectPublicKeyInfo: Expected algorithm OID");

        // SubjectPublicKey BIT STRING
        if (!reader.ReadBitString(out var publicKey))
            throw new FormatException("Invalid SubjectPublicKeyInfo: Expected subjectPublicKey BIT STRING");

        return (publicKey, algorithmOid);
    }

    private static SignatureAlgorithm ParseSignatureAlgorithm(string oid)
    {
        return oid switch
        {
            KazSign256Oid => SignatureAlgorithm.KazSign256,
            "2.16.458.1.1.1.1.2" => SignatureAlgorithm.KazSign192,
            "2.16.458.1.1.1.1.3" => SignatureAlgorithm.KazSign128,
            // Add more mappings as needed
            _ => throw new NotSupportedException($"Unknown signature algorithm OID: {oid}")
        };
    }

    private static string ComputeFingerprint(byte[] publicKey)
    {
        var hash = SHA256.HashData(publicKey);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}

/// <summary>
/// Simple ASN.1/DER reader for parsing CSRs.
/// </summary>
internal sealed class Asn1Reader
{
    private readonly byte[] _data;
    private int _position;

    public Asn1Reader(byte[] data)
    {
        _data = data;
        _position = 0;
    }

    public int Position => _position;
    public bool HasData => _position < _data.Length;

    public bool ReadSequence(out byte[] content)
    {
        content = [];
        if (!HasData || _data[_position] != 0x30) // SEQUENCE tag
            return false;

        _position++;
        if (!ReadLength(out var length))
            return false;

        content = _data[_position..(_position + length)];
        _position += length;
        return true;
    }

    public bool ReadSet(out byte[] content)
    {
        content = [];
        if (!HasData || _data[_position] != 0x31) // SET tag
            return false;

        _position++;
        if (!ReadLength(out var length))
            return false;

        content = _data[_position..(_position + length)];
        _position += length;
        return true;
    }

    public bool ReadInteger(out int value)
    {
        value = 0;
        if (!HasData || _data[_position] != 0x02) // INTEGER tag
            return false;

        _position++;
        if (!ReadLength(out var length))
            return false;

        for (var i = 0; i < length; i++)
        {
            value = (value << 8) | _data[_position + i];
        }
        _position += length;
        return true;
    }

    public bool ReadOid(out string oid)
    {
        oid = "";
        if (!HasData || _data[_position] != 0x06) // OBJECT IDENTIFIER tag
            return false;

        _position++;
        if (!ReadLength(out var length))
            return false;

        var oidBytes = _data[_position..(_position + length)];
        _position += length;

        oid = DecodeOid(oidBytes);
        return true;
    }

    public bool ReadBitString(out byte[] content)
    {
        content = [];
        if (!HasData || _data[_position] != 0x03) // BIT STRING tag
            return false;

        _position++;
        if (!ReadLength(out var length))
            return false;

        // First byte is unused bits count
        var unusedBits = _data[_position];
        content = _data[(_position + 1)..(_position + length)];
        _position += length;
        return true;
    }

    public bool ReadString(out string value)
    {
        value = "";
        if (!HasData)
            return false;

        var tag = _data[_position];
        // Accept UTF8String (0x0C), PrintableString (0x13), IA5String (0x16)
        if (tag is not (0x0C or 0x13 or 0x16))
            return false;

        _position++;
        if (!ReadLength(out var length))
            return false;

        value = Encoding.UTF8.GetString(_data, _position, length);
        _position += length;
        return true;
    }

    private bool ReadLength(out int length)
    {
        length = 0;
        if (!HasData)
            return false;

        var firstByte = _data[_position++];
        if (firstByte < 128)
        {
            length = firstByte;
            return true;
        }

        var numBytes = firstByte & 0x7F;
        if (_position + numBytes > _data.Length)
            return false;

        for (var i = 0; i < numBytes; i++)
        {
            length = (length << 8) | _data[_position++];
        }
        return true;
    }

    private static string DecodeOid(byte[] oidBytes)
    {
        var components = new List<int>();

        // First byte encodes first two components
        if (oidBytes.Length > 0)
        {
            components.Add(oidBytes[0] / 40);
            components.Add(oidBytes[0] % 40);
        }

        // Remaining bytes use variable-length encoding
        var value = 0;
        for (var i = 1; i < oidBytes.Length; i++)
        {
            var b = oidBytes[i];
            value = (value << 7) | (b & 0x7F);
            if ((b & 0x80) == 0)
            {
                components.Add(value);
                value = 0;
            }
        }

        return string.Join(".", components);
    }
}
