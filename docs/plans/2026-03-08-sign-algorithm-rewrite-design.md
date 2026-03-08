# KAZ-Sign Algorithm Rewrite Design

## Goal

Rewrite the C KAZ-Sign core algorithm (sign.c) to match the Java kaz-pqc-core
implementation exactly. The Java implementation is the source of truth.

## Why

The C and Java libraries implement fundamentally different signature schemes:

- **C (current):** 3-component (S1,S2,S3) signature with single modulus N,
  key pair (V, s||t), verification via V^S1 * S1^S2 * g2^S3 ≡ (g1*g2)^h mod N
- **Java (target):** 2-component (S1,S2) signature with composite modular system
  (G0,G1,q,Q,qQ,G1RHO,G1QRHO,G1qQRHO), key pair (v1+v2, SK+v1+v2),
  5-filter verification + two verification equations

Cross-platform key/signature interoperability is impossible until these match.

## Approach

In-place rewrite of sign.c. Replace algorithm internals while preserving:
- OpenSSL BIGNUM infrastructure and constant-time helpers
- API function signatures (sizes change, shapes don't)
- Extension modules (detached, DER, X.509, P12) with size updates
- KazWire encoding (already aligned)

## Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Message-recovery mode | Shim over detached | Java has no message-recovery; NIST API becomes concat shim |
| Hash per level | SHA-256/384/512 | Match Java exactly |
| Private key format | SK+v1+v2 | Match Java; enables verification filters during signing |
| Extension modules | Keep all, update sizes | Already built and tested; just need size/format updates |
| System parameters | Decimal string literals | Easy to verify against Java SystemParameters.java |

## New Parameter Sizes

| Level | Public Key (v1+v2) | Private Key (SK+v1+v2) | Hash | Sig (S1+S2) |
|-------|-------------------|----------------------|------|-------------|
| 128 | 49 (26+23) | 98 (49+26+23) | 32 (SHA-256) | 57 (49+8) |
| 192 | 73 (34+39) | 146 (73+34+39) | 48 (SHA-384) | 57 (73+8) |
| 256 | 97 (42+55) | 194 (97+42+55) | 64 (SHA-512) | 105 (97+8) |

## System Parameters

15+ large decimal constants per level from Java SystemParameters.java:

**Common (all levels):**
- G0, G1, g=6007, R=6151, A=324324000
- φ(G1), φ(φ(G1))

**Per-level:**
- q, Q, qQ, φ(Q), φ(qQ)
- G1RHO, G1QRHO, G1qQRHO
- φ(G1RHO), φ(φ(G1RHO))
- LG1RHO (bit-length: 208/271/336)

Stored as decimal string literals in sign.c, parsed to BIGNUMs via BN_dec2bn()
at init time.

## Key Generation

Matches KAZSIGNKeyGenerator.java:

```
KeyGen(level):
  1. a = random_4_bytes().nextProbablePrime()
  2. omega1 = random_4_bytes()
  3. b = a^(φφG1RHO) mod (omega1 * φG1RHO)
  4. G1A = G1 / A
  5. Loop:
     a. alpha = random((level + LG1RHO) / 8 bytes) * 2
     b. V1 = alpha mod G1RHO
     c. V2 = Q * alpha^(φQ * b) mod qQ
     d. SK = alpha^(φQ * b) mod G1qQRHO
     e. Accept if SK mod G1QRHO != 0 AND gcd(V1, G1A) == 1
  6. Return pk = (V1 || V2), sk = (SK || V1 || V2)
```

## Signing

Matches KAZSIGNSigner.java:

```
Sign(message, SK, V1, V2, level):
  1. hash = level_hash(message)
  2. hashInt = BigInteger(hash)
  3. r1 = random_4_bytes().nextPrime(), omega2 = random_4_bytes()
  4. r2 = random_4_bytes().nextPrime(), omega3 = random_4_bytes()
  5. beta1 = r1^(φφG1RHO) mod (omega2 * φG1RHO)
  6. beta2 = r2^(φφG1RHO) mod (omega3 * φG1RHO)
  7. S2 = 0
  8. Loop:
     a. term1 = hashInt^(φqQ * beta1) mod G1qQRHO
     b. term2 = hashInt^(φqQ * beta2) mod G1qQRHO
     c. S1 = SK * (term1 + term2) mod G1qQRHO
     d. Y1 = V1^φQ * 2*hashInt^φqQ mod G1QRHO
     e. SF1 = CRT(V2/Q, Y1, q, G1QRHO)
     f. Accept if bitlen(S1) == bitlen(G1qQRHO) AND S1 mod G1qQRHO != SF1
     g. Otherwise: S2++, hashInt++, retry
  9. Return (S1, S2)
```

## Verification

Matches KAZSIGNVerifier.java — 5 filters + 2 verification equations:

```
Verify(message, S1, S2, V1, V2, level):
  1. Filter 0: S2 <= 65535
  2. hash = level_hash(message), hashInt = BigInteger(hash) + S2
  3. Filter 1: S1 in [0, G1qQRHO)
  4. Filter 2: bitlen(S1) <= bitlen(G1qQRHO)
  5. Filter 3: S1 mod G1qQRHO != CRT(V2/Q, V1^φQ * 2*h^φqQ mod G1QRHO, q, G1QRHO)
  6. Filter 4: S1 mod (G1qQRHO/e) != CRT(V2/Q, Y2, qQ/e, G1RHO)
     where e = gcd(Q, G1RHO)
  7. Filter 5: 2*V2 - Q*S1 ≡ 0 (mod qQ)
  8. Verify: R^S1 ≡ R^(V1^φQ * 2*h^φqQ mod G1) (mod G0)
  9. Final: S1 * inv(V1^φQ, G1A) ≡ 2*h^φqQ (mod G1A)
     where G1A = G1RHO / A
```

## CRT Helper

Both signing and verification use Chinese Remainder Theorem for two moduli:

```
chrem(a1, a2, m1, m2):
  m1Inv = m1^(-1) mod m2
  diff = a2 - a1
  term = diff * m1 * m1Inv mod (m1 * m2)
  return (a1 + term) mod (m1 * m2)
```

## API Changes

### Functions with internal behavior change (same signature):
- `kaz_sign_keypair` / `kaz_sign_keypair_ex` — new keygen math, new key sizes
- `kaz_sign_signature` / `kaz_sign_signature_ex` — becomes detached-sign + append-message
- `kaz_sign_verify` / `kaz_sign_verify_ex` — becomes extract-message + detached-verify
- `kaz_sign_hash` / `kaz_sign_hash_ex` — SHA-256/384/512 per level

### Functions with size updates only:
- `kaz_sign_detached_ex` / `kaz_sign_verify_detached_ex`
- KazWire encode/decode
- DER encode/decode
- X.509/P12

### Functions unchanged:
- SHA3-256 standalone API, KDF, security utilities, error codes, version API

## Impact on sign.h

- Remove: `s_bytes`, `t_bytes`, `s3_bytes` from params struct
- Add: `sk_bytes`, `v1_bytes`, `v2_bytes`
- Update: all compile-time macros for new sizes
- Remove: `KAZ_SIGN_S3BYTES`, `KAZ_SIGN_SBYTES`, `KAZ_SIGN_TBYTES`, `KAZ_SIGN_VBYTES`
- Remove: `KAZ_SIGN_SP_N`, `KAZ_SIGN_SP_phiN`, `KAZ_SIGN_SP_Og1N`, `KAZ_SIGN_SP_Og2N`
- Update: `KAZ_SIGN_SIGNATURE_OVERHEAD` from S1+S2+S3 to S1+S2

## Impact on Extensions

- **detached.c:** Becomes primary sign/verify implementation. Simplified since
  signatures are natively detached.
- **der.c:** Key size constants update. DER wraps KazWire bytes (no format change).
- **x509.c:** Signature size constants update. Cert signing uses detached sign.
- **p12.c:** Key size constants update. No algorithm change.

## Impact on Bindings

Swift, C#, Android, Elixir bindings all hardcode key/signature sizes.
Must update to new sizes (49/73/97 pk, 98/146/194 sk, 57/81/105 sig).

## Testing

- All existing test patterns preserved (keygen, sign/verify round-trip, error cases)
- New tests for 5-filter verification edge cases
- Cross-validation test: compare C output against Java test vectors
- KAT vectors regenerated
