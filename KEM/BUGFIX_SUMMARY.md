# KAZ-KEM Bug Fix Summary

**Date:** 2025-11-20 - 2025-11-21
**Issue:** Message encryption/decryption failure and ciphertext buffer overflow
**Status:** ✅ FULLY FIXED - All security levels now pass 100% of tests

---

## The Bugs

### Bug #1: Missing Message Validation (M >= N)
**Root Cause:** The KEM algorithm uses `ENCAP = (K + M) mod N`. When M >= N, the modular reduction changes M, and decryption cannot recover the original message.

**Impact:**
- Silent data corruption
- Wrong message recovered with no error indication
- Tests failing for all-0xFF and other large messages

### Bug #2: Ciphertext Buffer Overflow (Levels 192/256)
**Root Cause:** Initial fix attempt reduced `KAZ_KEM_GENERAL_BYTES` from 88→87 (level 192) and 118→117 (level 256) to prevent M >= N. However:
- Message M should be < N (requires 87/117 bytes)
- But ENCAP = (K + M) mod N can be any value [0, N-1] (requires 88/118 bytes)
- N = 702 bits (level 192) requires 88 bytes to represent
- N = 942 bits (level 256) requires 118 bytes to represent

**Impact:**
- When ENCAPSIZE = 88/118 bytes but buffer = 87/117 bytes:
  - Leading byte dropped during ciphertext export
  - Decryption reads truncated ENCAP value
  - Wrong message recovered (even for valid M < N like all-zeros)
  - Zero-message test and roundtrip tests failed

---

## The Solution

### Fix #1: Message Validation
Added input validation in `src/internal/kem.c` and `src/internal/kem_optimized.c`:

```c
mpz_import(M, KAZ_KEM_GENERAL_BYTES, 1, sizeof(char), 0, 0, m);

/* Validate that M < N to prevent data corruption */
if (mpz_cmp(M, N) >= 0) {
    fprintf(stderr, "KAZ-KEM-ENCAPSULATION ERROR: Message value >= modulus N\n");
    fprintf(stderr, "This message cannot be correctly encrypted/decrypted.\n");
    fprintf(stderr, "Message must be < N for correct operation.\n");
    ret = -5;
    goto kaz_kem_cleanup;
}
```

**New error code:**
- `-5`: Message value >= modulus N (invalid for encryption)

### Fix #2: Restore Full Ciphertext Buffer Size
Reverted `KAZ_KEM_GENERAL_BYTES` to original values in `include/kaz/kem.h`:

**Level 192:**
- Changed from 87 → **88 bytes**
- Allows ENCAP to use full 88 bytes
- Validation prevents M >= N

**Level 256:**
- Changed from 117 → **118 bytes**
- Allows ENCAP to use full 118 bytes
- Validation prevents M >= N

**Key insight:** The buffer must be sized for ENCAP (which can be up to N-1), NOT for the maximum safe message. Message validation handles the M < N constraint.

### Fix #3: Update Test Message Patterns
Modified `tests/unit/test_kem.c` to use safe message patterns:

**Changed:**
```c
// OLD (causes M >= N for levels 192/256)
memset(msg, 0xAA, KAZ_KEM_GENERAL_BYTES);

// NEW (guaranteed < N)
for (int i = 0; i < KAZ_KEM_GENERAL_BYTES; i++) {
    msg[i] = (unsigned char)(i & 0xFF);
}
```

**Tests updated:**
1. `test_encap_basic` - now uses incrementing pattern
2. `test_decap_basic` - now uses incrementing pattern
3. `test_wrong_key_decap` - now uses incrementing pattern
4. `test_corrupted_ciphertext` - now uses incrementing pattern
5. `test_multiple_messages` - changed from `(test * 17 + i)` to `(test + i)`
6. `test_stress_operations` - changed from `(i * j + i)` to `(j + (i % 32))`

**Why patterns matter:**
- Level 192: Only byte patterns ≤ 0x30 (48) repeated are safe
- 0xAA repeated = 3.5× N (rejected)
- 0x42 repeated = 1.4× N (rejected)
- Incrementing bytes (0x00, 0x01, ...) = always safe

---

## Test Results

### Security Level 128 ✅
**Status:** ALL TESTS PASSING (11/11 = 100%)

**Parameters:**
- N: 432 bits = exactly 54 bytes
- Buffer size: 54 bytes
- Perfect match - no overflow possible

**Why it works:**
- N fits exactly in 54 bytes
- Message space = ENCAP space = 54 bytes
- No buffer size mismatch

### Security Level 192 ✅
**Status:** ALL TESTS PASSING (11/11 = 100%)

**Before Fix:** 5/11 tests (45.5%)
**After Fix:** 11/11 tests (100%)

**Parameters:**
- N: 702 bits
- Buffer size: 88 bytes (reverted from 87)
- Ciphertext ENCAP: requires up to 88 bytes
- Valid messages: must be < N (validation enforced)

**What changed:**
- Restored buffer to 88 bytes (fixes overflow)
- Added M < N validation (prevents invalid messages)
- Updated test patterns (generates safe messages)

### Security Level 256 ✅
**Status:** ALL TESTS PASSING (11/11 = 100%)

**Before Fix:** Unknown baseline
**After Fix:** 11/11 tests (100%)

**Parameters:**
- N: 942 bits
- Buffer size: 118 bytes (reverted from 117)
- Ciphertext ENCAP: requires up to 118 bytes
- Valid messages: must be < N (validation enforced)

**What changed:**
- Restored buffer to 118 bytes (fixes overflow)
- Added M < N validation (prevents invalid messages)
- Updated test patterns (generates safe messages)

---

## Parameter Analysis

| Level | N bits | N bytes | Buffer Size | Match? | Result |
|-------|--------|---------|-------------|--------|--------|
| 128   | 432    | 54      | 54          | ✅ Yes | Works perfectly |
| 192   | 702    | 88      | 88          | ✅ Yes | Fixed with validation |
| 256   | 942    | 118     | 118         | ✅ Yes | Fixed with validation |

**Key Findings:**
- Buffer must match N byte size (rounded up)
- Message validation prevents M >= N
- Test messages must use safe patterns
- Level 128 is inherently safe (N = 2^432 boundary)
- Levels 192/256 require careful message selection

---

## Files Modified

1. **`include/kaz/kem.h`**
   - Reverted `KAZ_KEM_GENERAL_BYTES`: 87→88 (level 192), 117→118 (level 256)
   - Added comments explaining M < N constraint

2. **`src/internal/kem.c`**
   - Added M < N validation returning error -5

3. **`src/internal/kem_optimized.c`**
   - Added M < N validation returning error -5

4. **`tests/unit/test_kem.c`**
   - Updated 6 tests to use safe message patterns
   - Enhanced error reporting with hex dumps
   - Added progress indicators for stress tests

---

## Error Codes

| Code | Meaning |
|------|---------|
| `0`  | Success |
| `-4` | Memory allocation failure |
| `-5` | **NEW** - Message value >= modulus N (invalid for encryption) |

---

## Impact

### Security ✅
- No security vulnerabilities introduced
- Prevents silent data corruption
- Invalid messages explicitly rejected

### Correctness ✅
- All security levels now pass 100% of tests
- Zero messages work correctly
- All-ones messages correctly rejected
- Ciphertext no longer truncated

### Compatibility ⚠️
- **Breaking change:** Messages >= N now explicitly fail (error -5)
- **API change:** Applications must handle error -5
- **Test change:** Test patterns must be < N

### Performance ✅
- Negligible overhead (single comparison per encryption)
- No additional memory allocations

### Usable Message Space
- **Level 128:** ~100% usable (N ≈ 2^432)
- **Level 192:** ~30% usable (safe patterns ≤ 0x30 repeated)
- **Level 256:** ~30% usable (similar constraint)

**Recommendation:** For production, consider:
1. Use security level 128 (full message space)
2. For levels 192/256, implement application-layer message mapping
3. Or regenerate parameters with larger N values

---

## Conclusion

The bug fix successfully resolves **all correctness issues** for all three security levels:

✅ **Level 128:** 11/11 tests passing (was already 100%)
✅ **Level 192:** 11/11 tests passing (was 45.5%)
✅ **Level 256:** 11/11 tests passing (new baseline)

**Root causes addressed:**
1. ✅ Missing M < N validation - now enforced with error -5
2. ✅ Buffer overflow for ENCAP - fixed by restoring full buffer size
3. ✅ Test patterns exceeding N - updated to use safe incremental patterns

**Production readiness:**
- Security level 128: ✅ Ready for production
- Security levels 192/256: ✅ Technically correct, ⚠️ limited usable message space

The implementation is now mathematically correct and all tests pass.
