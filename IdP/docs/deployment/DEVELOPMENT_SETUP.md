# Development Environment Setup

**Version:** 1.0.0
**Last Updated:** 2025-12-01

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Quick Start](#quick-start)
3. [SoftHSM2 Setup](#softhsm2-setup)
4. [Database Setup](#database-setup)
5. [Running the API](#running-the-api)
6. [Configuration](#configuration)
7. [Testing HSM Integration](#testing-hsm-integration)
8. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### Required Software

| Software | Version | Purpose |
|----------|---------|---------|
| Docker Desktop | 4.0+ | Container runtime |
| .NET SDK | 9.0+ | Backend development |
| Git | 2.0+ | Version control |

### Optional Software

| Software | Version | Purpose |
|----------|---------|---------|
| VS Code / Rider | Latest | IDE |
| Azure Data Studio | Latest | Database management |
| Postman / Bruno | Latest | API testing |

---

## Quick Start

### 1. Start Development Services

```bash
# Navigate to docker directory
cd deploy/docker

# Start all development services
docker-compose -f docker-compose.dev.yml up -d

# Check status
docker-compose -f docker-compose.dev.yml ps
```

### 2. Verify Services

```bash
# Check SoftHSM
docker exec idp-softhsm softhsm2-util --show-slots

# Check PostgreSQL
docker exec idp-postgres pg_isready -U idp

# Check Redis
docker exec idp-redis redis-cli ping
```

### 3. Run the API

```bash
# Navigate to API project
cd src/Backend/IdP.Api

# Run with development settings
dotnet run
```

### 4. Access Services

| Service | URL | Credentials |
|---------|-----|-------------|
| API | http://localhost:5000 | - |
| PostgreSQL | localhost:5432 | idp / idp_dev_password |
| Redis | localhost:6379 | - |
| MailHog UI | http://localhost:8025 | - |

---

## SoftHSM2 Setup

### What is SoftHSM2?

SoftHSM2 is a software implementation of a cryptographic store accessible through a PKCS#11 interface. It's designed to be used for development and testing when a hardware HSM is not available.

**Important:** SoftHSM2 is for development only. In production, use a real HSM (Azure Key Vault, AWS CloudHSM, Thales Luna, etc.)

### Docker Setup (Recommended)

The Docker Compose file includes SoftHSM2 pre-configured:

```bash
# Start SoftHSM container
docker-compose -f docker-compose.dev.yml up -d softhsm

# View initialized tokens
docker exec idp-softhsm softhsm2-util --show-slots
```

**Pre-configured Tokens:**

| Token Label | Purpose | Slot |
|-------------|---------|------|
| idp-root-ca | Platform Root CA key | 0 |
| idp-tenant-ca | Tenant CA keys | 1 |
| idp-jwt-signing | JWT signing keys | 2 |

**Default PINs (Development Only):**
- User PIN: `1234`
- SO PIN: `5678`

### Local Installation (Alternative)

If you prefer running SoftHSM2 locally:

**macOS:**
```bash
brew install softhsm

# Initialize configuration
mkdir -p ~/softhsm/tokens
echo "directories.tokendir = $HOME/softhsm/tokens" > ~/softhsm/softhsm2.conf
export SOFTHSM2_CONF=~/softhsm/softhsm2.conf

# Initialize a token
softhsm2-util --init-token --slot 0 --label "idp-dev" --pin 1234 --so-pin 5678
```

**Ubuntu/Debian:**
```bash
sudo apt-get install softhsm2

# Initialize token
softhsm2-util --init-token --slot 0 --label "idp-dev" --pin 1234 --so-pin 5678
```

**Windows:**
```powershell
# Download from: https://github.com/disig/SoftHSM2-for-Windows/releases
# Install and add to PATH

# Initialize token
softhsm2-util --init-token --slot 0 --label "idp-dev" --pin 1234 --so-pin 5678
```

### PKCS#11 Library Paths

| OS | Library Path |
|----|--------------|
| Docker | `/usr/lib/softhsm/libsofthsm2.so` |
| macOS (Homebrew) | `/opt/homebrew/lib/softhsm/libsofthsm2.so` |
| Ubuntu/Debian | `/usr/lib/softhsm/libsofthsm2.so` |
| Windows | `C:\SoftHSM2\lib\softhsm2.dll` |

---

## Database Setup

### Automatic Setup

The PostgreSQL container automatically runs initialization scripts:

```bash
# Start PostgreSQL
docker-compose -f docker-compose.dev.yml up -d postgres

# Verify schemas created
docker exec idp-postgres psql -U idp -d idp_db -c "\dn"
```

### Manual Migrations

```bash
# Navigate to Infrastructure project
cd src/Backend/Modules/Identity/IdP.Identity.Infrastructure

# Add migration
dotnet ef migrations add InitialCreate --startup-project ../../../IdP.Api

# Apply migrations
dotnet ef database update --startup-project ../../../IdP.Api
```

### Connection String

```
Host=localhost;Port=5432;Database=idp_db;Username=idp;Password=idp_dev_password
```

---

## Running the API

### Development Mode

```bash
cd src/Backend/IdP.Api
dotnet run --environment Development
```

### Watch Mode (Auto-reload)

```bash
dotnet watch run --environment Development
```

### With Docker

```bash
# Build and run API in Docker
docker-compose -f docker-compose.dev.yml up -d api
```

---

## Configuration

### appsettings.Development.json

```json
{
  "ConnectionStrings": {
    "DefaultConnection": "Host=localhost;Port=5432;Database=idp_db;Username=idp;Password=idp_dev_password"
  },

  "Redis": {
    "ConnectionString": "localhost:6379"
  },

  "Hsm": {
    "Provider": "Pkcs11",
    "Pkcs11": {
      "LibraryPath": "/usr/lib/softhsm/libsofthsm2.so",
      "TokenLabel": "idp-tenant-ca",
      "Pin": "1234"
    }
  },

  "Email": {
    "SmtpHost": "localhost",
    "SmtpPort": 1025,
    "FromAddress": "noreply@idp.local",
    "FromName": "IdP Development"
  },

  "Security": {
    "Attestation": {
      "Enabled": false,
      "AllowEmulators": true,
      "AllowDebugBuilds": true,
      "BypassToken": "dev-bypass-token-12345"
    }
  },

  "Logging": {
    "LogLevel": {
      "Default": "Debug",
      "Microsoft.AspNetCore": "Warning",
      "Microsoft.EntityFrameworkCore": "Information"
    }
  }
}
```

### Environment Variables

```bash
# HSM Configuration
export HSM_PROVIDER=Pkcs11
export HSM_PKCS11_LIBRARY=/usr/lib/softhsm/libsofthsm2.so
export HSM_PKCS11_TOKEN_LABEL=idp-tenant-ca
export HSM_PKCS11_PIN=1234

# Database
export CONNECTION_STRING="Host=localhost;Port=5432;Database=idp_db;Username=idp;Password=idp_dev_password"

# Redis
export REDIS_CONNECTION=localhost:6379
```

---

## Testing HSM Integration

### Generate a Test Key

```bash
# Enter the SoftHSM container
docker exec -it idp-softhsm bash

# Generate an RSA key (for testing PKCS#11 connectivity)
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
  --login --pin 1234 \
  --token-label "idp-tenant-ca" \
  --keypairgen --key-type rsa:2048 \
  --label "test-key" --id 01

# List keys
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
  --login --pin 1234 \
  --token-label "idp-tenant-ca" \
  --list-objects
```

### Test Signing

```bash
# Create test data
echo "Hello, HSM!" > /tmp/testdata.txt

# Sign with the key
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
  --login --pin 1234 \
  --token-label "idp-tenant-ca" \
  --sign --mechanism SHA256-RSA-PKCS \
  --label "test-key" \
  --input-file /tmp/testdata.txt \
  --output-file /tmp/signature.bin

echo "Signing successful!"
```

### .NET Integration Test

```csharp
// Quick test to verify PKCS#11 connectivity
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;

var factories = new Pkcs11InteropFactories();
using var pkcs11Library = factories.Pkcs11LibraryFactory.LoadPkcs11Library(
    factories,
    "/usr/lib/softhsm/libsofthsm2.so",
    AppType.SingleThreaded);

var slots = pkcs11Library.GetSlotList(SlotsType.WithTokenPresent);
foreach (var slot in slots)
{
    var tokenInfo = slot.GetTokenInfo();
    Console.WriteLine($"Token: {tokenInfo.Label}");
}
```

---

## Troubleshooting

### SoftHSM Token Not Found

```bash
# Check if tokens exist
docker exec idp-softhsm softhsm2-util --show-slots

# Re-initialize tokens
docker exec idp-softhsm /usr/local/bin/init-tokens.sh

# Check configuration
docker exec idp-softhsm cat /etc/softhsm/softhsm2.conf
```

### PKCS#11 Library Not Found

```bash
# Verify library exists
docker exec idp-softhsm ls -la /usr/lib/softhsm/

# Check library dependencies
docker exec idp-softhsm ldd /usr/lib/softhsm/libsofthsm2.so
```

### Database Connection Failed

```bash
# Check PostgreSQL is running
docker-compose -f docker-compose.dev.yml ps postgres

# Check logs
docker-compose -f docker-compose.dev.yml logs postgres

# Test connection
docker exec idp-postgres psql -U idp -d idp_db -c "SELECT 1"
```

### Permission Denied on Token Directory

```bash
# Fix permissions in container
docker exec idp-softhsm chmod -R 755 /var/lib/softhsm/tokens

# Or recreate volume
docker-compose -f docker-compose.dev.yml down -v
docker-compose -f docker-compose.dev.yml up -d
```

### Reset Everything

```bash
# Stop and remove all containers and volumes
docker-compose -f docker-compose.dev.yml down -v

# Rebuild and start fresh
docker-compose -f docker-compose.dev.yml up -d --build
```

---

## Development vs Production HSM

| Aspect | Development (SoftHSM2) | Production |
|--------|------------------------|------------|
| Key Storage | File-based | Hardware-protected |
| Security | Software-only | Tamper-resistant |
| Performance | Lower | Higher (hardware acceleration) |
| Certification | None | FIPS 140-2/3, Common Criteria |
| Cost | Free | $$$$ |
| Setup | Minutes | Days/Weeks |

### Migration Path

1. **Development:** Use SoftHSM2 with PKCS#11 interface
2. **Staging:** Use cloud HSM (Azure Key Vault, AWS CloudHSM)
3. **Production:** Use hardware HSM or managed cloud HSM

The PKCS#11 interface remains the same, so code changes are minimal when migrating.

---

## Next Steps

1. [Run the API locally](#running-the-api)
2. [Configure your IDE](./IDE_SETUP.md)
3. [Run tests](./TESTING.md)
4. [API Documentation](../api/README.md)

---

## References

- [SoftHSM2 GitHub](https://github.com/opendnssec/SoftHSMv2)
- [PKCS#11 Specification](http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html)
- [Pkcs11Interop .NET Library](https://github.com/Pkcs11Interop/Pkcs11Interop)
- [Docker Compose Documentation](https://docs.docker.com/compose/)
