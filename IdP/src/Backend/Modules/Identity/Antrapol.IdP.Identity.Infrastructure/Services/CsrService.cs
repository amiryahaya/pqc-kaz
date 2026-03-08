using System.Security.Cryptography;
using System.Text;
using Antrapol.IdP.Crypto.Domain.Enums;
using Antrapol.IdP.Crypto.Domain.Interfaces;
using Antrapol.IdP.Identity.Application.Interfaces;
using Antrapol.IdP.SharedKernel.Results;

namespace Antrapol.IdP.Identity.Infrastructure.Services;

/// <summary>
/// Service for parsing and validating Certificate Signing Requests (CSRs).
/// Uses KAZ-SIGN for signature verification via ICryptoProvider.
/// </summary>
public sealed class CsrService : ICsrService
{
    // KAZ-SIGN OIDs for each security level
    private const string KazSign128Oid = "2.16.458.1.1.1.1.1.128";
    private const string KazSign192Oid = "2.16.458.1.1.1.1.1.192";
    private const string KazSign256Oid = "2.16.458.1.1.1.1.1";  // Default/Legacy

    // Standard X.500 OIDs
    private const string OidCommonName = "2.5.4.3";
    private const string OidSerialNumber = "2.5.4.5";
    private const string OidCountry = "2.5.4.6";
    private const string OidOrganization = "2.5.4.10";
    private const string OidEmailAddress = "1.2.840.113549.1.9.1";

    private readonly ICryptoProvider _cryptoProvider;

    public CsrService(ICryptoProvider cryptoProvider)
    {
        _cryptoProvider = cryptoProvider;
    }

    public Result<CsrInfo> ParseCsr(string csrBase64)
    {
        try
        {
            var csrDer = Convert.FromBase64String(csrBase64);
            return ParseCsrDer(csrDer);
        }
        catch (FormatException)
        {
            return Error.Validation("CSR.InvalidBase64", "CSR is not valid Base64 encoded data");
        }
        catch (Exception ex)
        {
            return Error.Validation("CSR.ParseError", $"Failed to parse CSR: {ex.Message}");
        }
    }

    public bool VerifyCsrSignature(string csrBase64)
    {
        try
        {
            var csrDer = Convert.FromBase64String(csrBase64);
            return VerifyCsrSignatureDer(csrDer);
        }
        catch
        {
            return false;
        }
    }

    public string ComputePublicKeyFingerprint(byte[] publicKey)
    {
        var hash = SHA256.HashData(publicKey);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    public bool VerifySignature(byte[] publicKey, byte[] data, byte[] signature)
    {
        try
        {
            // Determine security level based on public key size
            var algorithm = GetAlgorithmFromPublicKeySize(publicKey.Length);
            return _cryptoProvider.VerifyAsync(data, signature, publicKey, algorithm).GetAwaiter().GetResult();
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Maps algorithm OID to KeyAlgorithm enum.
    /// </summary>
    private static KeyAlgorithm GetAlgorithmFromOid(string oid) => oid switch
    {
        KazSign128Oid => KeyAlgorithm.KazSign128,
        KazSign192Oid => KeyAlgorithm.KazSign192,
        KazSign256Oid => KeyAlgorithm.KazSign256,
        _ => KeyAlgorithm.KazSign256  // Default to 256 for legacy/unknown OIDs
    };

    /// <summary>
    /// Determines the KAZ-SIGN algorithm based on public key size.
    /// </summary>
    private static KeyAlgorithm GetAlgorithmFromPublicKeySize(int publicKeySize) => publicKeySize switch
    {
        54 => KeyAlgorithm.KazSign128,   // Level 128
        88 => KeyAlgorithm.KazSign192,   // Level 192
        118 => KeyAlgorithm.KazSign256,  // Level 256
        _ => KeyAlgorithm.KazSign256     // Default to 256 for unknown sizes
    };

    private Result<CsrInfo> ParseCsrDer(byte[] csrDer)
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
            if (!tbsReader.ReadInteger(out _))
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
            var (publicKey, _) = ParseSubjectPublicKeyInfo(spkiContent);

            // Compute public key fingerprint
            var fingerprint = ComputePublicKeyFingerprint(publicKey);

            return new CsrInfo(
                SubjectDn: subjectDn,
                PublicKey: publicKey,
                PublicKeyFingerprint: fingerprint,
                CsrData: csrDer);
        }
        catch (Exception ex)
        {
            return Error.Validation("CSR.ParseError", $"Failed to parse CSR: {ex.Message}");
        }
    }

    private bool VerifyCsrSignatureDer(byte[] csrDer)
    {
        try
        {
            var reader = new Asn1Reader(csrDer);

            // CertificationRequest SEQUENCE
            if (!reader.ReadSequence(out var csrContent))
                return false;

            var csrReader = new Asn1Reader(csrContent);

            // CertificationRequestInfo SEQUENCE (TBS data)
            var tbsStart = csrReader.Position;
            if (!csrReader.ReadSequence(out var tbsContent))
                return false;
            var tbsEnd = csrReader.Position;
            var tbsData = csrDer[tbsStart..tbsEnd];

            var tbsReader = new Asn1Reader(tbsContent);

            // Skip Version
            if (!tbsReader.ReadInteger(out _))
                return false;

            // Skip Subject
            if (!tbsReader.ReadSequence(out _))
                return false;

            // SubjectPublicKeyInfo SEQUENCE
            if (!tbsReader.ReadSequence(out var spkiContent))
                return false;
            var (publicKey, _) = ParseSubjectPublicKeyInfo(spkiContent);

            // SignatureAlgorithm SEQUENCE
            if (!csrReader.ReadSequence(out var sigAlgContent))
                return false;
            var sigAlgReader = new Asn1Reader(sigAlgContent);
            if (!sigAlgReader.ReadOid(out var signatureAlgorithmOid))
                return false;

            // Verify it's a KAZ-SIGN algorithm
            var algorithm = GetAlgorithmFromOid(signatureAlgorithmOid);
            if (algorithm is not (KeyAlgorithm.KazSign128 or KeyAlgorithm.KazSign192 or KeyAlgorithm.KazSign256))
                return false;

            // Signature BIT STRING
            if (!csrReader.ReadBitString(out var signature))
                return false;

            // Verify the signature using the appropriate algorithm
            return _cryptoProvider.VerifyAsync(tbsData, signature, publicKey, algorithm).GetAwaiter().GetResult();
        }
        catch
        {
            return false;
        }
    }

    private static (string? CommonName, string? SerialNumber, string? Country, string? Organization, string? EmailAddress) ParseSubjectDn(byte[] subjectContent)
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

        return (commonName, serialNumber, country, organization, emailAddress);
    }

    private static string BuildSubjectDnString((string? CommonName, string? SerialNumber, string? Country, string? Organization, string? EmailAddress) subject)
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
