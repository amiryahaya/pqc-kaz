/**
 * KAZ-SIGN Elixir NIF Bindings
 *
 * Provides native Elixir bindings for the KAZ-SIGN post-quantum
 * digital signature scheme.
 */

#include <erl_nif.h>
#include <string.h>
#include <stdbool.h>
#include "kaz/sign.h"

/* Thread safety for initialization */
static ErlNifMutex *kaz_mutex = NULL;
static bool is_loaded = false;

/* Atoms */
static ERL_NIF_TERM atom_ok;
static ERL_NIF_TERM atom_error;
static ERL_NIF_TERM atom_true;
static ERL_NIF_TERM atom_false;
static ERL_NIF_TERM atom_public_key;
static ERL_NIF_TERM atom_private_key;
static ERL_NIF_TERM atom_signature;
static ERL_NIF_TERM atom_message;

/* Error atoms */
static ERL_NIF_TERM atom_invalid_level;
static ERL_NIF_TERM atom_not_initialized;
static ERL_NIF_TERM atom_init_failed;
static ERL_NIF_TERM atom_keypair_failed;
static ERL_NIF_TERM atom_sign_failed;
static ERL_NIF_TERM atom_verify_failed;
static ERL_NIF_TERM atom_invalid_argument;
static ERL_NIF_TERM atom_memory_error;
static ERL_NIF_TERM atom_invalid_signature;
static ERL_NIF_TERM atom_der_error;
static ERL_NIF_TERM atom_x509_error;
static ERL_NIF_TERM atom_p12_error;
static ERL_NIF_TERM atom_hash_error;
static ERL_NIF_TERM atom_buffer_error;

/* Certificate/P12 atoms */
static ERL_NIF_TERM atom_cert;
static ERL_NIF_TERM atom_chain;
static ERL_NIF_TERM atom_level;

/* Helper: Create atom */
static ERL_NIF_TERM make_atom(ErlNifEnv *env, const char *name) {
    ERL_NIF_TERM atom;
    if (enif_make_existing_atom(env, name, &atom, ERL_NIF_LATIN1)) {
        return atom;
    }
    return enif_make_atom(env, name);
}

/* Helper: Create error tuple */
static ERL_NIF_TERM make_error(ErlNifEnv *env, ERL_NIF_TERM reason) {
    return enif_make_tuple2(env, atom_error, reason);
}

/* Helper: Create ok tuple */
static ERL_NIF_TERM make_ok(ErlNifEnv *env, ERL_NIF_TERM value) {
    return enif_make_tuple2(env, atom_ok, value);
}

/* Helper: Map KAZ error code to atom */
static ERL_NIF_TERM error_code_to_atom(ErlNifEnv *env, int code) {
    switch (code) {
        case KAZ_SIGN_ERROR_MEMORY:
            return atom_memory_error;
        case KAZ_SIGN_ERROR_RNG:
            return make_atom(env, "rng_failed");
        case KAZ_SIGN_ERROR_INVALID:
            return atom_invalid_argument;
        case KAZ_SIGN_ERROR_VERIFY:
            return atom_invalid_signature;
        case KAZ_SIGN_ERROR_DER:
            return atom_der_error;
        case KAZ_SIGN_ERROR_X509:
            return atom_x509_error;
        case KAZ_SIGN_ERROR_P12:
            return atom_p12_error;
        case KAZ_SIGN_ERROR_HASH:
            return atom_hash_error;
        case KAZ_SIGN_ERROR_BUFFER:
            return atom_buffer_error;
        default:
            return make_atom(env, "unknown_error");
    }
}

/* Helper: Get level enum from int */
static kaz_sign_level_t int_to_level(int level) {
    switch (level) {
        case 128: return KAZ_LEVEL_128;
        case 192: return KAZ_LEVEL_192;
        case 256: return KAZ_LEVEL_256;
        default: return (kaz_sign_level_t)-1;
    }
}

/**
 * Initialize KAZ-SIGN random number generator.
 *
 * Returns: :ok | {:error, reason}
 */
static ERL_NIF_TERM sign_init(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    (void)argc;
    (void)argv;

    enif_mutex_lock(kaz_mutex);
    int result = kaz_sign_init_random();
    enif_mutex_unlock(kaz_mutex);

    if (result != KAZ_SIGN_SUCCESS) {
        return make_error(env, atom_init_failed);
    }

    return atom_ok;
}

/**
 * Initialize a specific security level.
 *
 * Args: [level :: 128 | 192 | 256]
 * Returns: :ok | {:error, reason}
 */
static ERL_NIF_TERM nif_init_level(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    int level;

    if (argc != 1 || !enif_get_int(env, argv[0], &level)) {
        return enif_make_badarg(env);
    }

    kaz_sign_level_t kaz_level = int_to_level(level);
    if ((int)kaz_level == -1) {
        return make_error(env, atom_invalid_level);
    }

    enif_mutex_lock(kaz_mutex);

    /* Initialize RNG if not already */
    if (!kaz_sign_is_initialized()) {
        int result = kaz_sign_init_random();
        if (result != KAZ_SIGN_SUCCESS) {
            enif_mutex_unlock(kaz_mutex);
            return make_error(env, atom_init_failed);
        }
    }

    int result = kaz_sign_init_level(kaz_level);
    enif_mutex_unlock(kaz_mutex);

    if (result != KAZ_SIGN_SUCCESS) {
        return make_error(env, atom_init_failed);
    }

    return atom_ok;
}

/**
 * Check if KAZ-SIGN is initialized.
 *
 * Returns: boolean()
 */
static ERL_NIF_TERM nif_is_initialized(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    (void)argc;
    (void)argv;

    if (kaz_sign_is_initialized()) {
        return atom_true;
    }
    return atom_false;
}

/**
 * Get sizes for a specific security level.
 *
 * Args: [level :: 128 | 192 | 256]
 * Returns: {:ok, %{...}} | {:error, reason}
 */
static ERL_NIF_TERM nif_get_sizes(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    int level;

    if (argc != 1 || !enif_get_int(env, argv[0], &level)) {
        return enif_make_badarg(env);
    }

    kaz_sign_level_t kaz_level = int_to_level(level);
    if ((int)kaz_level == -1) {
        return make_error(env, atom_invalid_level);
    }

    const kaz_sign_level_params_t *params = kaz_sign_get_level_params(kaz_level);
    if (params == NULL) {
        return make_error(env, atom_invalid_level);
    }

    ERL_NIF_TERM map = enif_make_new_map(env);

    enif_make_map_put(env, map, atom_public_key,
                      enif_make_uint64(env, params->public_key_bytes), &map);
    enif_make_map_put(env, map, atom_private_key,
                      enif_make_uint64(env, params->secret_key_bytes), &map);
    enif_make_map_put(env, map, make_atom(env, "hash"),
                      enif_make_uint64(env, params->hash_bytes), &map);
    enif_make_map_put(env, map, make_atom(env, "signature_overhead"),
                      enif_make_uint64(env, params->signature_overhead), &map);

    return make_ok(env, map);
}

/**
 * Generate a signing keypair.
 *
 * Args: [level :: 128 | 192 | 256]
 * Returns: {:ok, %{public_key: binary, private_key: binary}} | {:error, reason}
 */
static ERL_NIF_TERM nif_keypair(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    int level;

    if (argc != 1 || !enif_get_int(env, argv[0], &level)) {
        return enif_make_badarg(env);
    }

    kaz_sign_level_t kaz_level = int_to_level(level);
    if ((int)kaz_level == -1) {
        return make_error(env, atom_invalid_level);
    }

    const kaz_sign_level_params_t *params = kaz_sign_get_level_params(kaz_level);
    if (params == NULL) {
        return make_error(env, atom_invalid_level);
    }

    size_t pk_size = params->public_key_bytes;
    size_t sk_size = params->secret_key_bytes;

    ERL_NIF_TERM pk_term, sk_term;
    unsigned char *pk = enif_make_new_binary(env, pk_size, &pk_term);
    unsigned char *sk = enif_make_new_binary(env, sk_size, &sk_term);

    if (pk == NULL || sk == NULL) {
        return make_error(env, atom_memory_error);
    }

    enif_mutex_lock(kaz_mutex);

    /* Ensure initialized */
    if (!kaz_sign_is_initialized()) {
        int init_result = kaz_sign_init_random();
        if (init_result != KAZ_SIGN_SUCCESS) {
            enif_mutex_unlock(kaz_mutex);
            return make_error(env, atom_init_failed);
        }
    }

    int result = kaz_sign_keypair_ex(kaz_level, pk, sk);
    enif_mutex_unlock(kaz_mutex);

    if (result != KAZ_SIGN_SUCCESS) {
        return make_error(env, error_code_to_atom(env, result));
    }

    ERL_NIF_TERM map = enif_make_new_map(env);
    enif_make_map_put(env, map, atom_public_key, pk_term, &map);
    enif_make_map_put(env, map, atom_private_key, sk_term, &map);

    return make_ok(env, map);
}

/**
 * Sign a message.
 *
 * Args: [level :: integer, message :: binary, private_key :: binary]
 * Returns: {:ok, signature} | {:error, reason}
 */
static ERL_NIF_TERM nif_sign(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    int level;
    ErlNifBinary msg_bin, sk_bin;

    if (argc != 3) {
        return enif_make_badarg(env);
    }

    if (!enif_get_int(env, argv[0], &level) ||
        !enif_inspect_binary(env, argv[1], &msg_bin) ||
        !enif_inspect_binary(env, argv[2], &sk_bin)) {
        return enif_make_badarg(env);
    }

    kaz_sign_level_t kaz_level = int_to_level(level);
    if ((int)kaz_level == -1) {
        return make_error(env, atom_invalid_level);
    }

    const kaz_sign_level_params_t *params = kaz_sign_get_level_params(kaz_level);
    if (params == NULL) {
        return make_error(env, atom_invalid_level);
    }

    if (sk_bin.size != params->secret_key_bytes) {
        return make_error(env, make_atom(env, "invalid_private_key_size"));
    }

    /* Signature size = overhead + message length */
    size_t sig_max_size = params->signature_overhead + msg_bin.size;

    ERL_NIF_TERM sig_term;
    unsigned char *sig = enif_make_new_binary(env, sig_max_size, &sig_term);

    if (sig == NULL) {
        return make_error(env, atom_memory_error);
    }

    unsigned long long sig_len;

    enif_mutex_lock(kaz_mutex);

    /* Ensure initialized */
    if (!kaz_sign_is_initialized()) {
        int init_result = kaz_sign_init_random();
        if (init_result != KAZ_SIGN_SUCCESS) {
            enif_mutex_unlock(kaz_mutex);
            return make_error(env, atom_init_failed);
        }
    }

    int result = kaz_sign_signature_ex(kaz_level, sig, &sig_len,
                                        msg_bin.data, msg_bin.size,
                                        sk_bin.data);
    enif_mutex_unlock(kaz_mutex);

    if (result != KAZ_SIGN_SUCCESS) {
        return make_error(env, error_code_to_atom(env, result));
    }

    /* Resize to actual signature length */
    if (sig_len < sig_max_size) {
        ERL_NIF_TERM resized;
        unsigned char *new_sig = enif_make_new_binary(env, sig_len, &resized);
        if (new_sig == NULL) {
            return make_error(env, atom_memory_error);
        }
        memcpy(new_sig, sig, sig_len);
        return make_ok(env, resized);
    }

    return make_ok(env, sig_term);
}

/**
 * Verify a signature and recover the message.
 *
 * Args: [level :: integer, signature :: binary, public_key :: binary]
 * Returns: {:ok, message} | {:error, :invalid_signature} | {:error, reason}
 */
static ERL_NIF_TERM nif_verify(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    int level;
    ErlNifBinary sig_bin, pk_bin;

    if (argc != 3) {
        return enif_make_badarg(env);
    }

    if (!enif_get_int(env, argv[0], &level) ||
        !enif_inspect_binary(env, argv[1], &sig_bin) ||
        !enif_inspect_binary(env, argv[2], &pk_bin)) {
        return enif_make_badarg(env);
    }

    kaz_sign_level_t kaz_level = int_to_level(level);
    if ((int)kaz_level == -1) {
        return make_error(env, atom_invalid_level);
    }

    const kaz_sign_level_params_t *params = kaz_sign_get_level_params(kaz_level);
    if (params == NULL) {
        return make_error(env, atom_invalid_level);
    }

    if (pk_bin.size != params->public_key_bytes) {
        return make_error(env, make_atom(env, "invalid_public_key_size"));
    }

    if (sig_bin.size < params->signature_overhead) {
        return make_error(env, atom_invalid_signature);
    }

    /* Message size is signature size minus overhead */
    size_t msg_max_size = sig_bin.size - params->signature_overhead;

    unsigned char *msg = enif_alloc(msg_max_size + 1);
    if (msg == NULL) {
        return make_error(env, atom_memory_error);
    }

    unsigned long long msg_len;

    enif_mutex_lock(kaz_mutex);

    /* Ensure initialized */
    if (!kaz_sign_is_initialized()) {
        int init_result = kaz_sign_init_random();
        if (init_result != KAZ_SIGN_SUCCESS) {
            enif_mutex_unlock(kaz_mutex);
            enif_free(msg);
            return make_error(env, atom_init_failed);
        }
    }

    int result = kaz_sign_verify_ex(kaz_level, msg, &msg_len,
                                     sig_bin.data, sig_bin.size,
                                     pk_bin.data);
    enif_mutex_unlock(kaz_mutex);

    if (result != KAZ_SIGN_SUCCESS) {
        enif_free(msg);
        return make_error(env, atom_invalid_signature);
    }

    ERL_NIF_TERM msg_term;
    unsigned char *msg_out = enif_make_new_binary(env, msg_len, &msg_term);
    if (msg_out == NULL) {
        enif_free(msg);
        return make_error(env, atom_memory_error);
    }
    memcpy(msg_out, msg, msg_len);

    enif_free(msg);

    return make_ok(env, msg_term);
}

/**
 * Hash a message using the level-specific hash function.
 *
 * Args: [level :: integer, message :: binary]
 * Returns: {:ok, hash} | {:error, reason}
 */
static ERL_NIF_TERM nif_hash(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    int level;
    ErlNifBinary msg_bin;

    if (argc != 2) {
        return enif_make_badarg(env);
    }

    if (!enif_get_int(env, argv[0], &level) ||
        !enif_inspect_binary(env, argv[1], &msg_bin)) {
        return enif_make_badarg(env);
    }

    kaz_sign_level_t kaz_level = int_to_level(level);
    if ((int)kaz_level == -1) {
        return make_error(env, atom_invalid_level);
    }

    const kaz_sign_level_params_t *params = kaz_sign_get_level_params(kaz_level);
    if (params == NULL) {
        return make_error(env, atom_invalid_level);
    }

    ERL_NIF_TERM hash_term;
    unsigned char *hash = enif_make_new_binary(env, params->hash_bytes, &hash_term);

    if (hash == NULL) {
        return make_error(env, atom_memory_error);
    }

    int result = kaz_sign_hash_ex(kaz_level, msg_bin.data, msg_bin.size, hash);

    if (result != KAZ_SIGN_SUCCESS) {
        return make_error(env, error_code_to_atom(env, result));
    }

    return make_ok(env, hash_term);
}

/**
 * Create a detached signature (signature does not include the message).
 *
 * Args: [level :: integer, message :: binary, private_key :: binary]
 * Returns: {:ok, signature} | {:error, reason}
 */
static ERL_NIF_TERM nif_sign_detached(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    int level;
    ErlNifBinary msg_bin, sk_bin;

    if (argc != 3) {
        return enif_make_badarg(env);
    }

    if (!enif_get_int(env, argv[0], &level) ||
        !enif_inspect_binary(env, argv[1], &msg_bin) ||
        !enif_inspect_binary(env, argv[2], &sk_bin)) {
        return enif_make_badarg(env);
    }

    kaz_sign_level_t kaz_level = int_to_level(level);
    if ((int)kaz_level == -1) {
        return make_error(env, atom_invalid_level);
    }

    const kaz_sign_level_params_t *params = kaz_sign_get_level_params(kaz_level);
    if (params == NULL) {
        return make_error(env, atom_invalid_level);
    }

    if (sk_bin.size != params->secret_key_bytes) {
        return make_error(env, make_atom(env, "invalid_private_key_size"));
    }

    size_t sig_max_size = kaz_sign_detached_sig_bytes(kaz_level);
    if (sig_max_size == 0) {
        return make_error(env, atom_invalid_level);
    }

    ERL_NIF_TERM sig_term;
    unsigned char *sig = enif_make_new_binary(env, sig_max_size, &sig_term);

    if (sig == NULL) {
        return make_error(env, atom_memory_error);
    }

    unsigned long long sig_len;

    enif_mutex_lock(kaz_mutex);

    /* Ensure initialized */
    if (!kaz_sign_is_initialized()) {
        int init_result = kaz_sign_init_random();
        if (init_result != KAZ_SIGN_SUCCESS) {
            enif_mutex_unlock(kaz_mutex);
            return make_error(env, atom_init_failed);
        }
    }

    int result = kaz_sign_detached_ex(kaz_level, sig, &sig_len,
                                       msg_bin.data, msg_bin.size,
                                       sk_bin.data);
    enif_mutex_unlock(kaz_mutex);

    if (result != KAZ_SIGN_SUCCESS) {
        return make_error(env, error_code_to_atom(env, result));
    }

    /* Resize to actual signature length */
    if (sig_len < sig_max_size) {
        ERL_NIF_TERM resized;
        unsigned char *new_sig = enif_make_new_binary(env, sig_len, &resized);
        if (new_sig == NULL) {
            return make_error(env, atom_memory_error);
        }
        memcpy(new_sig, sig, sig_len);
        return make_ok(env, resized);
    }

    return make_ok(env, sig_term);
}

/**
 * Verify a detached signature.
 *
 * Args: [level :: integer, message :: binary, signature :: binary, public_key :: binary]
 * Returns: {:ok, true} | {:ok, false} | {:error, reason}
 */
static ERL_NIF_TERM nif_verify_detached(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    int level;
    ErlNifBinary msg_bin, sig_bin, pk_bin;

    if (argc != 4) {
        return enif_make_badarg(env);
    }

    if (!enif_get_int(env, argv[0], &level) ||
        !enif_inspect_binary(env, argv[1], &msg_bin) ||
        !enif_inspect_binary(env, argv[2], &sig_bin) ||
        !enif_inspect_binary(env, argv[3], &pk_bin)) {
        return enif_make_badarg(env);
    }

    kaz_sign_level_t kaz_level = int_to_level(level);
    if ((int)kaz_level == -1) {
        return make_error(env, atom_invalid_level);
    }

    const kaz_sign_level_params_t *params = kaz_sign_get_level_params(kaz_level);
    if (params == NULL) {
        return make_error(env, atom_invalid_level);
    }

    if (pk_bin.size != params->public_key_bytes) {
        return make_error(env, make_atom(env, "invalid_public_key_size"));
    }

    enif_mutex_lock(kaz_mutex);

    /* Ensure initialized */
    if (!kaz_sign_is_initialized()) {
        int init_result = kaz_sign_init_random();
        if (init_result != KAZ_SIGN_SUCCESS) {
            enif_mutex_unlock(kaz_mutex);
            return make_error(env, atom_init_failed);
        }
    }

    int result = kaz_sign_verify_detached_ex(kaz_level,
                                              sig_bin.data, sig_bin.size,
                                              msg_bin.data, msg_bin.size,
                                              pk_bin.data);
    enif_mutex_unlock(kaz_mutex);

    if (result == KAZ_SIGN_SUCCESS) {
        return make_ok(env, atom_true);
    }

    return make_ok(env, atom_false);
}

/**
 * Compute SHA3-256 hash.
 *
 * Args: [data :: binary]
 * Returns: {:ok, hash} | {:error, reason}
 */
static ERL_NIF_TERM nif_sha3_256(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    ErlNifBinary data_bin;

    if (argc != 1) {
        return enif_make_badarg(env);
    }

    if (!enif_inspect_binary(env, argv[0], &data_bin)) {
        return enif_make_badarg(env);
    }

    ERL_NIF_TERM hash_term;
    unsigned char *hash = enif_make_new_binary(env, 32, &hash_term);

    if (hash == NULL) {
        return make_error(env, atom_memory_error);
    }

    int result = kaz_sha3_256(data_bin.data, data_bin.size, hash);

    if (result != KAZ_SIGN_SUCCESS) {
        return make_error(env, error_code_to_atom(env, result));
    }

    return make_ok(env, hash_term);
}

/**
 * Encode a public key to DER format.
 *
 * Args: [level :: integer, public_key :: binary]
 * Returns: {:ok, der} | {:error, reason}
 */
static ERL_NIF_TERM nif_pubkey_to_der(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    int level;
    ErlNifBinary pk_bin;

    if (argc != 2) {
        return enif_make_badarg(env);
    }

    if (!enif_get_int(env, argv[0], &level) ||
        !enif_inspect_binary(env, argv[1], &pk_bin)) {
        return enif_make_badarg(env);
    }

    kaz_sign_level_t kaz_level = int_to_level(level);
    if ((int)kaz_level == -1) {
        return make_error(env, atom_invalid_level);
    }

    const kaz_sign_level_params_t *params = kaz_sign_get_level_params(kaz_level);
    if (params == NULL) {
        return make_error(env, atom_invalid_level);
    }

    if (pk_bin.size != params->public_key_bytes) {
        return make_error(env, make_atom(env, "invalid_public_key_size"));
    }

    /* Allocate generous buffer for DER encoding */
    unsigned long long der_len = pk_bin.size + 256;
    unsigned char *der_buf = enif_alloc(der_len);
    if (der_buf == NULL) {
        return make_error(env, atom_memory_error);
    }

    int result = kaz_sign_pubkey_to_der(kaz_level, pk_bin.data, der_buf, &der_len);

    if (result != KAZ_SIGN_SUCCESS) {
        enif_free(der_buf);
        return make_error(env, error_code_to_atom(env, result));
    }

    ERL_NIF_TERM der_term;
    unsigned char *der_out = enif_make_new_binary(env, der_len, &der_term);
    if (der_out == NULL) {
        enif_free(der_buf);
        return make_error(env, atom_memory_error);
    }
    memcpy(der_out, der_buf, der_len);

    enif_free(der_buf);

    return make_ok(env, der_term);
}

/**
 * Decode a public key from DER format.
 *
 * Args: [level :: integer, der :: binary]
 * Returns: {:ok, public_key} | {:error, reason}
 */
static ERL_NIF_TERM nif_pubkey_from_der(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    int level;
    ErlNifBinary der_bin;

    if (argc != 2) {
        return enif_make_badarg(env);
    }

    if (!enif_get_int(env, argv[0], &level) ||
        !enif_inspect_binary(env, argv[1], &der_bin)) {
        return enif_make_badarg(env);
    }

    kaz_sign_level_t kaz_level = int_to_level(level);
    if ((int)kaz_level == -1) {
        return make_error(env, atom_invalid_level);
    }

    const kaz_sign_level_params_t *params = kaz_sign_get_level_params(kaz_level);
    if (params == NULL) {
        return make_error(env, atom_invalid_level);
    }

    ERL_NIF_TERM pk_term;
    unsigned char *pk = enif_make_new_binary(env, params->public_key_bytes, &pk_term);

    if (pk == NULL) {
        return make_error(env, atom_memory_error);
    }

    int result = kaz_sign_pubkey_from_der(kaz_level, der_bin.data, der_bin.size, pk);

    if (result != KAZ_SIGN_SUCCESS) {
        return make_error(env, error_code_to_atom(env, result));
    }

    return make_ok(env, pk_term);
}

/**
 * Encode a private key to DER format.
 *
 * Args: [level :: integer, private_key :: binary]
 * Returns: {:ok, der} | {:error, reason}
 */
static ERL_NIF_TERM nif_privkey_to_der(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    int level;
    ErlNifBinary sk_bin;

    if (argc != 2) {
        return enif_make_badarg(env);
    }

    if (!enif_get_int(env, argv[0], &level) ||
        !enif_inspect_binary(env, argv[1], &sk_bin)) {
        return enif_make_badarg(env);
    }

    kaz_sign_level_t kaz_level = int_to_level(level);
    if ((int)kaz_level == -1) {
        return make_error(env, atom_invalid_level);
    }

    const kaz_sign_level_params_t *params = kaz_sign_get_level_params(kaz_level);
    if (params == NULL) {
        return make_error(env, atom_invalid_level);
    }

    if (sk_bin.size != params->secret_key_bytes) {
        return make_error(env, make_atom(env, "invalid_private_key_size"));
    }

    /* Allocate generous buffer for DER encoding */
    unsigned long long der_len = sk_bin.size + 256;
    unsigned char *der_buf = enif_alloc(der_len);
    if (der_buf == NULL) {
        return make_error(env, atom_memory_error);
    }

    int result = kaz_sign_privkey_to_der(kaz_level, sk_bin.data, der_buf, &der_len);

    if (result != KAZ_SIGN_SUCCESS) {
        enif_free(der_buf);
        return make_error(env, error_code_to_atom(env, result));
    }

    ERL_NIF_TERM der_term;
    unsigned char *der_out = enif_make_new_binary(env, der_len, &der_term);
    if (der_out == NULL) {
        enif_free(der_buf);
        return make_error(env, atom_memory_error);
    }
    memcpy(der_out, der_buf, der_len);

    enif_free(der_buf);

    return make_ok(env, der_term);
}

/**
 * Decode a private key from DER format.
 *
 * Args: [level :: integer, der :: binary]
 * Returns: {:ok, private_key} | {:error, reason}
 */
static ERL_NIF_TERM nif_privkey_from_der(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    int level;
    ErlNifBinary der_bin;

    if (argc != 2) {
        return enif_make_badarg(env);
    }

    if (!enif_get_int(env, argv[0], &level) ||
        !enif_inspect_binary(env, argv[1], &der_bin)) {
        return enif_make_badarg(env);
    }

    kaz_sign_level_t kaz_level = int_to_level(level);
    if ((int)kaz_level == -1) {
        return make_error(env, atom_invalid_level);
    }

    const kaz_sign_level_params_t *params = kaz_sign_get_level_params(kaz_level);
    if (params == NULL) {
        return make_error(env, atom_invalid_level);
    }

    ERL_NIF_TERM sk_term;
    unsigned char *sk = enif_make_new_binary(env, params->secret_key_bytes, &sk_term);

    if (sk == NULL) {
        return make_error(env, atom_memory_error);
    }

    int result = kaz_sign_privkey_from_der(kaz_level, der_bin.data, der_bin.size, sk);

    if (result != KAZ_SIGN_SUCCESS) {
        return make_error(env, error_code_to_atom(env, result));
    }

    return make_ok(env, sk_term);
}

/**
 * Generate a PKCS#10 Certificate Signing Request (CSR).
 *
 * Args: [level :: integer, private_key :: binary, public_key :: binary, subject :: binary]
 * Returns: {:ok, csr} | {:error, reason}
 */
static ERL_NIF_TERM nif_generate_csr(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    int level;
    ErlNifBinary sk_bin, pk_bin;
    char subject[1024];

    if (argc != 4) {
        return enif_make_badarg(env);
    }

    if (!enif_get_int(env, argv[0], &level) ||
        !enif_inspect_binary(env, argv[1], &sk_bin) ||
        !enif_inspect_binary(env, argv[2], &pk_bin) ||
        !enif_get_string(env, argv[3], subject, sizeof(subject), ERL_NIF_LATIN1)) {
        return enif_make_badarg(env);
    }

    kaz_sign_level_t kaz_level = int_to_level(level);
    if ((int)kaz_level == -1) {
        return make_error(env, atom_invalid_level);
    }

    const kaz_sign_level_params_t *params = kaz_sign_get_level_params(kaz_level);
    if (params == NULL) {
        return make_error(env, atom_invalid_level);
    }

    if (sk_bin.size != params->secret_key_bytes) {
        return make_error(env, make_atom(env, "invalid_private_key_size"));
    }

    if (pk_bin.size != params->public_key_bytes) {
        return make_error(env, make_atom(env, "invalid_public_key_size"));
    }

    /* Allocate generous buffer for CSR */
    unsigned long long csr_len = 4096;
    unsigned char *csr_buf = enif_alloc(csr_len);
    if (csr_buf == NULL) {
        return make_error(env, atom_memory_error);
    }

    enif_mutex_lock(kaz_mutex);

    /* Ensure initialized */
    if (!kaz_sign_is_initialized()) {
        int init_result = kaz_sign_init_random();
        if (init_result != KAZ_SIGN_SUCCESS) {
            enif_mutex_unlock(kaz_mutex);
            enif_free(csr_buf);
            return make_error(env, atom_init_failed);
        }
    }

    int result = kaz_sign_generate_csr(kaz_level, sk_bin.data, pk_bin.data,
                                        subject, csr_buf, &csr_len);
    enif_mutex_unlock(kaz_mutex);

    if (result != KAZ_SIGN_SUCCESS) {
        enif_free(csr_buf);
        return make_error(env, error_code_to_atom(env, result));
    }

    ERL_NIF_TERM csr_term;
    unsigned char *csr_out = enif_make_new_binary(env, csr_len, &csr_term);
    if (csr_out == NULL) {
        enif_free(csr_buf);
        return make_error(env, atom_memory_error);
    }
    memcpy(csr_out, csr_buf, csr_len);

    enif_free(csr_buf);

    return make_ok(env, csr_term);
}

/**
 * Verify a PKCS#10 CSR self-signature.
 *
 * Args: [level :: integer, csr :: binary]
 * Returns: {:ok, true} | {:ok, false} | {:error, reason}
 */
static ERL_NIF_TERM nif_verify_csr(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    int level;
    ErlNifBinary csr_bin;

    if (argc != 2) {
        return enif_make_badarg(env);
    }

    if (!enif_get_int(env, argv[0], &level) ||
        !enif_inspect_binary(env, argv[1], &csr_bin)) {
        return enif_make_badarg(env);
    }

    kaz_sign_level_t kaz_level = int_to_level(level);
    if ((int)kaz_level == -1) {
        return make_error(env, atom_invalid_level);
    }

    enif_mutex_lock(kaz_mutex);

    /* Ensure initialized */
    if (!kaz_sign_is_initialized()) {
        int init_result = kaz_sign_init_random();
        if (init_result != KAZ_SIGN_SUCCESS) {
            enif_mutex_unlock(kaz_mutex);
            return make_error(env, atom_init_failed);
        }
    }

    int result = kaz_sign_verify_csr(kaz_level, csr_bin.data, csr_bin.size);
    enif_mutex_unlock(kaz_mutex);

    if (result == KAZ_SIGN_SUCCESS) {
        return make_ok(env, atom_true);
    }

    return make_ok(env, atom_false);
}

/**
 * Issue an X.509 certificate by signing a CSR.
 *
 * Args: [level :: integer, issuer_sk :: binary, issuer_pk :: binary,
 *        issuer_name :: charlist, csr :: binary, serial :: integer, days :: integer]
 * Returns: {:ok, cert} | {:error, reason}
 */
static ERL_NIF_TERM nif_issue_certificate(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    int level, days;
    ErlNifBinary sk_bin, pk_bin, csr_bin;
    char issuer_name[1024];
    unsigned long long serial;

    if (argc != 7) {
        return enif_make_badarg(env);
    }

    if (!enif_get_int(env, argv[0], &level) ||
        !enif_inspect_binary(env, argv[1], &sk_bin) ||
        !enif_inspect_binary(env, argv[2], &pk_bin) ||
        !enif_get_string(env, argv[3], issuer_name, sizeof(issuer_name), ERL_NIF_LATIN1) ||
        !enif_inspect_binary(env, argv[4], &csr_bin) ||
        !enif_get_uint64(env, argv[5], &serial) ||
        !enif_get_int(env, argv[6], &days)) {
        return enif_make_badarg(env);
    }

    kaz_sign_level_t kaz_level = int_to_level(level);
    if ((int)kaz_level == -1) {
        return make_error(env, atom_invalid_level);
    }

    const kaz_sign_level_params_t *params = kaz_sign_get_level_params(kaz_level);
    if (params == NULL) {
        return make_error(env, atom_invalid_level);
    }

    if (sk_bin.size != params->secret_key_bytes) {
        return make_error(env, make_atom(env, "invalid_private_key_size"));
    }

    if (pk_bin.size != params->public_key_bytes) {
        return make_error(env, make_atom(env, "invalid_public_key_size"));
    }

    /* Allocate generous buffer for certificate */
    unsigned long long cert_len = 8192;
    unsigned char *cert_buf = enif_alloc(cert_len);
    if (cert_buf == NULL) {
        return make_error(env, atom_memory_error);
    }

    enif_mutex_lock(kaz_mutex);

    /* Ensure initialized */
    if (!kaz_sign_is_initialized()) {
        int init_result = kaz_sign_init_random();
        if (init_result != KAZ_SIGN_SUCCESS) {
            enif_mutex_unlock(kaz_mutex);
            enif_free(cert_buf);
            return make_error(env, atom_init_failed);
        }
    }

    int result = kaz_sign_issue_certificate(kaz_level, sk_bin.data, pk_bin.data,
                                             issuer_name, csr_bin.data, csr_bin.size,
                                             serial, days, cert_buf, &cert_len);
    enif_mutex_unlock(kaz_mutex);

    if (result != KAZ_SIGN_SUCCESS) {
        enif_free(cert_buf);
        return make_error(env, error_code_to_atom(env, result));
    }

    ERL_NIF_TERM cert_term;
    unsigned char *cert_out = enif_make_new_binary(env, cert_len, &cert_term);
    if (cert_out == NULL) {
        enif_free(cert_buf);
        return make_error(env, atom_memory_error);
    }
    memcpy(cert_out, cert_buf, cert_len);

    enif_free(cert_buf);

    return make_ok(env, cert_term);
}

/**
 * Verify an X.509 certificate signature against an issuer public key.
 *
 * Args: [level :: integer, cert :: binary, issuer_pk :: binary]
 * Returns: {:ok, true} | {:ok, false} | {:error, reason}
 */
static ERL_NIF_TERM nif_verify_certificate(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    int level;
    ErlNifBinary cert_bin, pk_bin;

    if (argc != 3) {
        return enif_make_badarg(env);
    }

    if (!enif_get_int(env, argv[0], &level) ||
        !enif_inspect_binary(env, argv[1], &cert_bin) ||
        !enif_inspect_binary(env, argv[2], &pk_bin)) {
        return enif_make_badarg(env);
    }

    kaz_sign_level_t kaz_level = int_to_level(level);
    if ((int)kaz_level == -1) {
        return make_error(env, atom_invalid_level);
    }

    const kaz_sign_level_params_t *params = kaz_sign_get_level_params(kaz_level);
    if (params == NULL) {
        return make_error(env, atom_invalid_level);
    }

    if (pk_bin.size != params->public_key_bytes) {
        return make_error(env, make_atom(env, "invalid_public_key_size"));
    }

    enif_mutex_lock(kaz_mutex);

    /* Ensure initialized */
    if (!kaz_sign_is_initialized()) {
        int init_result = kaz_sign_init_random();
        if (init_result != KAZ_SIGN_SUCCESS) {
            enif_mutex_unlock(kaz_mutex);
            return make_error(env, atom_init_failed);
        }
    }

    int result = kaz_sign_verify_certificate(kaz_level, cert_bin.data, cert_bin.size,
                                              pk_bin.data);
    enif_mutex_unlock(kaz_mutex);

    if (result == KAZ_SIGN_SUCCESS) {
        return make_ok(env, atom_true);
    }

    return make_ok(env, atom_false);
}

/**
 * Extract the public key from an X.509 certificate.
 *
 * Args: [level :: integer, cert :: binary]
 * Returns: {:ok, public_key} | {:error, reason}
 */
static ERL_NIF_TERM nif_cert_extract_pubkey(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    int level;
    ErlNifBinary cert_bin;

    if (argc != 2) {
        return enif_make_badarg(env);
    }

    if (!enif_get_int(env, argv[0], &level) ||
        !enif_inspect_binary(env, argv[1], &cert_bin)) {
        return enif_make_badarg(env);
    }

    kaz_sign_level_t kaz_level = int_to_level(level);
    if ((int)kaz_level == -1) {
        return make_error(env, atom_invalid_level);
    }

    const kaz_sign_level_params_t *params = kaz_sign_get_level_params(kaz_level);
    if (params == NULL) {
        return make_error(env, atom_invalid_level);
    }

    ERL_NIF_TERM pk_term;
    unsigned char *pk = enif_make_new_binary(env, params->public_key_bytes, &pk_term);

    if (pk == NULL) {
        return make_error(env, atom_memory_error);
    }

    enif_mutex_lock(kaz_mutex);

    /* Ensure initialized */
    if (!kaz_sign_is_initialized()) {
        int init_result = kaz_sign_init_random();
        if (init_result != KAZ_SIGN_SUCCESS) {
            enif_mutex_unlock(kaz_mutex);
            return make_error(env, atom_init_failed);
        }
    }

    int result = kaz_sign_cert_extract_pubkey(kaz_level, cert_bin.data, cert_bin.size, pk);
    enif_mutex_unlock(kaz_mutex);

    if (result != KAZ_SIGN_SUCCESS) {
        return make_error(env, error_code_to_atom(env, result));
    }

    return make_ok(env, pk_term);
}

/**
 * Create a PKCS#12 keystore.
 *
 * Args: [level :: integer, private_key :: binary, public_key :: binary,
 *        cert :: binary, password :: charlist, name :: charlist]
 * Returns: {:ok, p12} | {:error, reason}
 */
static ERL_NIF_TERM nif_create_p12(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    int level;
    ErlNifBinary sk_bin, pk_bin, cert_bin;
    char password[256];
    char name[256];

    if (argc != 6) {
        return enif_make_badarg(env);
    }

    if (!enif_get_int(env, argv[0], &level) ||
        !enif_inspect_binary(env, argv[1], &sk_bin) ||
        !enif_inspect_binary(env, argv[2], &pk_bin) ||
        !enif_inspect_binary(env, argv[3], &cert_bin) ||
        !enif_get_string(env, argv[4], password, sizeof(password), ERL_NIF_LATIN1) ||
        !enif_get_string(env, argv[5], name, sizeof(name), ERL_NIF_LATIN1)) {
        return enif_make_badarg(env);
    }

    kaz_sign_level_t kaz_level = int_to_level(level);
    if ((int)kaz_level == -1) {
        return make_error(env, atom_invalid_level);
    }

    const kaz_sign_level_params_t *params = kaz_sign_get_level_params(kaz_level);
    if (params == NULL) {
        return make_error(env, atom_invalid_level);
    }

    if (sk_bin.size != params->secret_key_bytes) {
        return make_error(env, make_atom(env, "invalid_private_key_size"));
    }

    if (pk_bin.size != params->public_key_bytes) {
        return make_error(env, make_atom(env, "invalid_public_key_size"));
    }

    /* Allocate generous buffer for P12 */
    unsigned long long p12_len = 16384;
    unsigned char *p12_buf = enif_alloc(p12_len);
    if (p12_buf == NULL) {
        return make_error(env, atom_memory_error);
    }

    const unsigned char *cert_data = cert_bin.size > 0 ? cert_bin.data : NULL;
    unsigned long long cert_len = cert_bin.size;

    enif_mutex_lock(kaz_mutex);

    /* Ensure initialized */
    if (!kaz_sign_is_initialized()) {
        int init_result = kaz_sign_init_random();
        if (init_result != KAZ_SIGN_SUCCESS) {
            enif_mutex_unlock(kaz_mutex);
            enif_free(p12_buf);
            return make_error(env, atom_init_failed);
        }
    }

    int result = kaz_sign_create_p12(kaz_level, sk_bin.data, pk_bin.data,
                                      cert_data, cert_len,
                                      password, name, p12_buf, &p12_len);
    enif_mutex_unlock(kaz_mutex);

    if (result != KAZ_SIGN_SUCCESS) {
        enif_free(p12_buf);
        return make_error(env, error_code_to_atom(env, result));
    }

    ERL_NIF_TERM p12_term;
    unsigned char *p12_out = enif_make_new_binary(env, p12_len, &p12_term);
    if (p12_out == NULL) {
        enif_free(p12_buf);
        return make_error(env, atom_memory_error);
    }
    memcpy(p12_out, p12_buf, p12_len);

    enif_free(p12_buf);

    return make_ok(env, p12_term);
}

/**
 * Load a key pair and certificate from a PKCS#12 keystore.
 *
 * Args: [level :: integer, p12 :: binary, password :: charlist]
 * Returns: {:ok, %{private_key: binary, public_key: binary, cert: binary}} | {:error, reason}
 */
static ERL_NIF_TERM nif_load_p12(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    int level;
    ErlNifBinary p12_bin;
    char password[256];

    if (argc != 3) {
        return enif_make_badarg(env);
    }

    if (!enif_get_int(env, argv[0], &level) ||
        !enif_inspect_binary(env, argv[1], &p12_bin) ||
        !enif_get_string(env, argv[2], password, sizeof(password), ERL_NIF_LATIN1)) {
        return enif_make_badarg(env);
    }

    kaz_sign_level_t kaz_level = int_to_level(level);
    if ((int)kaz_level == -1) {
        return make_error(env, atom_invalid_level);
    }

    const kaz_sign_level_params_t *params = kaz_sign_get_level_params(kaz_level);
    if (params == NULL) {
        return make_error(env, atom_invalid_level);
    }

    unsigned char *sk = enif_alloc(params->secret_key_bytes);
    unsigned char *pk = enif_alloc(params->public_key_bytes);
    unsigned long long cert_len = 8192;
    unsigned char *cert_buf = enif_alloc(cert_len);

    if (sk == NULL || pk == NULL || cert_buf == NULL) {
        if (sk) enif_free(sk);
        if (pk) enif_free(pk);
        if (cert_buf) enif_free(cert_buf);
        return make_error(env, atom_memory_error);
    }

    enif_mutex_lock(kaz_mutex);

    /* Ensure initialized */
    if (!kaz_sign_is_initialized()) {
        int init_result = kaz_sign_init_random();
        if (init_result != KAZ_SIGN_SUCCESS) {
            enif_mutex_unlock(kaz_mutex);
            enif_free(sk);
            enif_free(pk);
            enif_free(cert_buf);
            return make_error(env, atom_init_failed);
        }
    }

    int result = kaz_sign_load_p12(kaz_level, p12_bin.data, p12_bin.size,
                                    password, sk, pk, cert_buf, &cert_len);
    enif_mutex_unlock(kaz_mutex);

    if (result != KAZ_SIGN_SUCCESS) {
        enif_free(sk);
        enif_free(pk);
        enif_free(cert_buf);
        return make_error(env, error_code_to_atom(env, result));
    }

    ERL_NIF_TERM sk_term, pk_term, cert_term;
    unsigned char *sk_out = enif_make_new_binary(env, params->secret_key_bytes, &sk_term);
    unsigned char *pk_out = enif_make_new_binary(env, params->public_key_bytes, &pk_term);

    if (sk_out == NULL || pk_out == NULL) {
        enif_free(sk);
        enif_free(pk);
        enif_free(cert_buf);
        return make_error(env, atom_memory_error);
    }

    memcpy(sk_out, sk, params->secret_key_bytes);
    memcpy(pk_out, pk, params->public_key_bytes);

    if (cert_len > 0) {
        unsigned char *cert_out = enif_make_new_binary(env, cert_len, &cert_term);
        if (cert_out == NULL) {
            enif_free(sk);
            enif_free(pk);
            enif_free(cert_buf);
            return make_error(env, atom_memory_error);
        }
        memcpy(cert_out, cert_buf, cert_len);
    } else {
        enif_make_new_binary(env, 0, &cert_term);
    }

    enif_free(sk);
    enif_free(pk);
    enif_free(cert_buf);

    ERL_NIF_TERM map = enif_make_new_map(env);
    enif_make_map_put(env, map, atom_private_key, sk_term, &map);
    enif_make_map_put(env, map, atom_public_key, pk_term, &map);
    enif_make_map_put(env, map, atom_cert, cert_term, &map);

    return make_ok(env, map);
}

/**
 * Cleanup KAZ-SIGN state.
 *
 * Returns: :ok
 */
static ERL_NIF_TERM nif_cleanup(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    (void)argc;
    (void)argv;

    enif_mutex_lock(kaz_mutex);
    kaz_sign_clear_all();
    kaz_sign_clear_random();
    enif_mutex_unlock(kaz_mutex);

    return atom_ok;
}

/**
 * Get KAZ-SIGN version string.
 *
 * Returns: version_string
 */
static ERL_NIF_TERM nif_version(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    (void)argc;
    (void)argv;

    const char *version = kaz_sign_version();
    return enif_make_string(env, version, ERL_NIF_LATIN1);
}

/* NIF initialization */
static int load(ErlNifEnv *env, void **priv_data, ERL_NIF_TERM load_info) {
    (void)priv_data;
    (void)load_info;

    /* Create mutex for thread safety */
    kaz_mutex = enif_mutex_create("kaz_sign_mutex");
    if (kaz_mutex == NULL) {
        return -1;
    }

    /* Initialize atoms */
    atom_ok = make_atom(env, "ok");
    atom_error = make_atom(env, "error");
    atom_true = make_atom(env, "true");
    atom_false = make_atom(env, "false");
    atom_public_key = make_atom(env, "public_key");
    atom_private_key = make_atom(env, "private_key");
    atom_signature = make_atom(env, "signature");
    atom_message = make_atom(env, "message");

    atom_invalid_level = make_atom(env, "invalid_level");
    atom_not_initialized = make_atom(env, "not_initialized");
    atom_init_failed = make_atom(env, "init_failed");
    atom_keypair_failed = make_atom(env, "keypair_failed");
    atom_sign_failed = make_atom(env, "sign_failed");
    atom_verify_failed = make_atom(env, "verify_failed");
    atom_invalid_argument = make_atom(env, "invalid_argument");
    atom_memory_error = make_atom(env, "memory_error");
    atom_invalid_signature = make_atom(env, "invalid_signature");
    atom_der_error = make_atom(env, "der_error");
    atom_x509_error = make_atom(env, "x509_error");
    atom_p12_error = make_atom(env, "p12_error");
    atom_hash_error = make_atom(env, "hash_error");
    atom_buffer_error = make_atom(env, "buffer_error");

    atom_cert = make_atom(env, "cert");
    atom_chain = make_atom(env, "chain");
    atom_level = make_atom(env, "level");

    is_loaded = true;

    return 0;
}

static void unload(ErlNifEnv *env, void *priv_data) {
    (void)env;
    (void)priv_data;

    if (kaz_mutex != NULL) {
        enif_mutex_lock(kaz_mutex);
        kaz_sign_clear_all();
        kaz_sign_clear_random();
        enif_mutex_unlock(kaz_mutex);
        enif_mutex_destroy(kaz_mutex);
        kaz_mutex = NULL;
    }

    is_loaded = false;
}

static int upgrade(ErlNifEnv *env, void **priv_data, void **old_priv_data, ERL_NIF_TERM load_info) {
    (void)old_priv_data;
    return load(env, priv_data, load_info);
}

/* NIF function table */
static ErlNifFunc nif_funcs[] = {
    {"nif_init", 0, sign_init, 0},
    {"nif_init_level", 1, nif_init_level, 0},
    {"nif_is_initialized", 0, nif_is_initialized, 0},
    {"nif_get_sizes", 1, nif_get_sizes, 0},
    {"nif_keypair", 1, nif_keypair, 0},
    {"nif_sign", 3, nif_sign, 0},
    {"nif_verify", 3, nif_verify, 0},
    {"nif_hash", 2, nif_hash, 0},
    {"nif_sign_detached", 3, nif_sign_detached, 0},
    {"nif_verify_detached", 4, nif_verify_detached, 0},
    {"nif_sha3_256", 1, nif_sha3_256, 0},
    {"nif_pubkey_to_der", 2, nif_pubkey_to_der, 0},
    {"nif_pubkey_from_der", 2, nif_pubkey_from_der, 0},
    {"nif_privkey_to_der", 2, nif_privkey_to_der, 0},
    {"nif_privkey_from_der", 2, nif_privkey_from_der, 0},
    {"nif_generate_csr", 4, nif_generate_csr, 0},
    {"nif_verify_csr", 2, nif_verify_csr, 0},
    {"nif_issue_certificate", 7, nif_issue_certificate, 0},
    {"nif_verify_certificate", 3, nif_verify_certificate, 0},
    {"nif_cert_extract_pubkey", 2, nif_cert_extract_pubkey, 0},
    {"nif_create_p12", 6, nif_create_p12, 0},
    {"nif_load_p12", 3, nif_load_p12, 0},
    {"nif_cleanup", 0, nif_cleanup, 0},
    {"nif_version", 0, nif_version, 0}
};

ERL_NIF_INIT(Elixir.KazSign.Nif, nif_funcs, load, NULL, upgrade, unload)
