/**
 * KAZ-KEM JNI Bridge
 * Provides Java Native Interface for the KAZ-KEM library
 */

#include <jni.h>
#include <string.h>
#include <stdlib.h>
#include <android/log.h>

// Include KAZ-KEM headers
extern "C" {
#include "kaz/kem.h"
#include "kaz/security.h"
}

#define LOG_TAG "KazKemJNI"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// Helper to throw Java exceptions
static void throwException(JNIEnv *env, const char *className, const char *message) {
    jclass exClass = env->FindClass(className);
    if (exClass != nullptr) {
        env->ThrowNew(exClass, message);
    }
}

// Helper to throw KazKemException
static void throwKazKemException(JNIEnv *env, int errorCode, const char *message) {
    jclass exClass = env->FindClass("com/antrapol/kaz/kem/KazKemException");
    if (exClass != nullptr) {
        jmethodID constructor = env->GetMethodID(exClass, "<init>", "(ILjava/lang/String;)V");
        if (constructor != nullptr) {
            jstring jmsg = env->NewStringUTF(message);
            jthrowable exception = (jthrowable)env->NewObject(exClass, constructor, errorCode, jmsg);
            env->Throw(exception);
        }
    }
}

// Securely zero memory
static void secureZero(void *ptr, size_t size) {
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (size--) {
        *p++ = 0;
    }
}

extern "C" {

// ============================================================================
// Initialization Functions
// ============================================================================

JNIEXPORT jint JNICALL
Java_com_antrapol_kaz_kem_KazKemNative_nativeInit(JNIEnv *env, jclass clazz, jint level) {
    int result = kaz_kem_init(level);
    if (result != 0) {
        LOGE("kaz_kem_init failed with code %d", result);
    }
    return result;
}

JNIEXPORT jboolean JNICALL
Java_com_antrapol_kaz_kem_KazKemNative_nativeIsInitialized(JNIEnv *env, jclass clazz) {
    return kaz_kem_is_initialized() != 0;
}

JNIEXPORT jint JNICALL
Java_com_antrapol_kaz_kem_KazKemNative_nativeGetLevel(JNIEnv *env, jclass clazz) {
    return kaz_kem_get_level();
}

JNIEXPORT void JNICALL
Java_com_antrapol_kaz_kem_KazKemNative_nativeCleanup(JNIEnv *env, jclass clazz) {
    kaz_kem_cleanup();
}

// ============================================================================
// Size Functions
// ============================================================================

JNIEXPORT jint JNICALL
Java_com_antrapol_kaz_kem_KazKemNative_nativePublicKeyBytes(JNIEnv *env, jclass clazz) {
    return (jint)kaz_kem_publickey_bytes();
}

JNIEXPORT jint JNICALL
Java_com_antrapol_kaz_kem_KazKemNative_nativePrivateKeyBytes(JNIEnv *env, jclass clazz) {
    return (jint)kaz_kem_privatekey_bytes();
}

JNIEXPORT jint JNICALL
Java_com_antrapol_kaz_kem_KazKemNative_nativeCiphertextBytes(JNIEnv *env, jclass clazz) {
    return (jint)kaz_kem_ciphertext_bytes();
}

JNIEXPORT jint JNICALL
Java_com_antrapol_kaz_kem_KazKemNative_nativeSharedSecretBytes(JNIEnv *env, jclass clazz) {
    return (jint)kaz_kem_shared_secret_bytes();
}

// ============================================================================
// Key Generation
// ============================================================================

JNIEXPORT jobjectArray JNICALL
Java_com_antrapol_kaz_kem_KazKemNative_nativeKeyPair(JNIEnv *env, jclass clazz) {
    size_t pkSize = kaz_kem_publickey_bytes();
    size_t skSize = kaz_kem_privatekey_bytes();

    unsigned char *pk = (unsigned char *)malloc(pkSize);
    unsigned char *sk = (unsigned char *)malloc(skSize);

    if (pk == nullptr || sk == nullptr) {
        free(pk);
        free(sk);
        throwKazKemException(env, -2, "Memory allocation failed");
        return nullptr;
    }

    int result = kaz_kem_keypair(pk, sk);
    if (result != 0) {
        secureZero(sk, skSize);
        free(pk);
        free(sk);
        throwKazKemException(env, result, "Key generation failed");
        return nullptr;
    }

    // Create byte arrays
    jbyteArray publicKey = env->NewByteArray(pkSize);
    jbyteArray privateKey = env->NewByteArray(skSize);

    if (publicKey == nullptr || privateKey == nullptr) {
        secureZero(sk, skSize);
        free(pk);
        free(sk);
        throwKazKemException(env, -2, "Failed to create byte arrays");
        return nullptr;
    }

    env->SetByteArrayRegion(publicKey, 0, pkSize, (jbyte *)pk);
    env->SetByteArrayRegion(privateKey, 0, skSize, (jbyte *)sk);

    // Secure cleanup
    secureZero(sk, skSize);
    free(pk);
    free(sk);

    // Create result array [publicKey, privateKey]
    jclass byteArrayClass = env->FindClass("[B");
    jobjectArray result_array = env->NewObjectArray(2, byteArrayClass, nullptr);
    env->SetObjectArrayElement(result_array, 0, publicKey);
    env->SetObjectArrayElement(result_array, 1, privateKey);

    return result_array;
}

// ============================================================================
// Encapsulation
// ============================================================================

JNIEXPORT jobjectArray JNICALL
Java_com_antrapol_kaz_kem_KazKemNative_nativeEncapsulate(JNIEnv *env, jclass clazz,
                                                    jbyteArray sharedSecret,
                                                    jbyteArray publicKey) {
    // Get input data
    jsize ssLen = env->GetArrayLength(sharedSecret);
    jsize pkLen = env->GetArrayLength(publicKey);

    jbyte *ssData = env->GetByteArrayElements(sharedSecret, nullptr);
    jbyte *pkData = env->GetByteArrayElements(publicKey, nullptr);

    if (ssData == nullptr || pkData == nullptr) {
        if (ssData) env->ReleaseByteArrayElements(sharedSecret, ssData, JNI_ABORT);
        if (pkData) env->ReleaseByteArrayElements(publicKey, pkData, JNI_ABORT);
        throwKazKemException(env, -2, "Failed to get array elements");
        return nullptr;
    }

    // Allocate ciphertext buffer
    size_t ctSize = kaz_kem_ciphertext_bytes();
    unsigned char *ct = (unsigned char *)malloc(ctSize);
    if (ct == nullptr) {
        env->ReleaseByteArrayElements(sharedSecret, ssData, JNI_ABORT);
        env->ReleaseByteArrayElements(publicKey, pkData, JNI_ABORT);
        throwKazKemException(env, -2, "Memory allocation failed");
        return nullptr;
    }

    unsigned long long ctLen = 0;

    int result = kaz_kem_encapsulate(
        ct, &ctLen,
        (const unsigned char *)ssData, (unsigned long long)ssLen,
        (const unsigned char *)pkData
    );

    env->ReleaseByteArrayElements(sharedSecret, ssData, JNI_ABORT);
    env->ReleaseByteArrayElements(publicKey, pkData, JNI_ABORT);

    if (result != 0) {
        free(ct);
        throwKazKemException(env, result, "Encapsulation failed");
        return nullptr;
    }

    // Create ciphertext byte array
    jbyteArray ciphertext = env->NewByteArray(ctLen);
    if (ciphertext == nullptr) {
        free(ct);
        throwKazKemException(env, -2, "Failed to create ciphertext array");
        return nullptr;
    }

    env->SetByteArrayRegion(ciphertext, 0, ctLen, (jbyte *)ct);
    free(ct);

    // Return [ciphertext]
    jclass byteArrayClass = env->FindClass("[B");
    jobjectArray result_array = env->NewObjectArray(1, byteArrayClass, nullptr);
    env->SetObjectArrayElement(result_array, 0, ciphertext);

    return result_array;
}

// ============================================================================
// Decapsulation
// ============================================================================

JNIEXPORT jbyteArray JNICALL
Java_com_antrapol_kaz_kem_KazKemNative_nativeDecapsulate(JNIEnv *env, jclass clazz,
                                                    jbyteArray ciphertext,
                                                    jbyteArray privateKey) {
    // Get input data
    jsize ctLen = env->GetArrayLength(ciphertext);
    jsize skLen = env->GetArrayLength(privateKey);

    jbyte *ctData = env->GetByteArrayElements(ciphertext, nullptr);
    jbyte *skData = env->GetByteArrayElements(privateKey, nullptr);

    if (ctData == nullptr || skData == nullptr) {
        if (ctData) env->ReleaseByteArrayElements(ciphertext, ctData, JNI_ABORT);
        if (skData) env->ReleaseByteArrayElements(privateKey, skData, JNI_ABORT);
        throwKazKemException(env, -2, "Failed to get array elements");
        return nullptr;
    }

    // Allocate shared secret buffer
    size_t ssSize = kaz_kem_shared_secret_bytes();
    unsigned char *ss = (unsigned char *)malloc(ssSize);
    if (ss == nullptr) {
        env->ReleaseByteArrayElements(ciphertext, ctData, JNI_ABORT);
        env->ReleaseByteArrayElements(privateKey, skData, JNI_ABORT);
        throwKazKemException(env, -2, "Memory allocation failed");
        return nullptr;
    }

    unsigned long long ssLen = 0;

    int result = kaz_kem_decapsulate(
        ss, &ssLen,
        (const unsigned char *)ctData, (unsigned long long)ctLen,
        (const unsigned char *)skData
    );

    env->ReleaseByteArrayElements(ciphertext, ctData, JNI_ABORT);
    env->ReleaseByteArrayElements(privateKey, skData, JNI_ABORT);

    if (result != 0) {
        secureZero(ss, ssSize);
        free(ss);
        throwKazKemException(env, result, "Decapsulation failed");
        return nullptr;
    }

    // Create shared secret byte array
    jbyteArray sharedSecret = env->NewByteArray(ssLen);
    if (sharedSecret == nullptr) {
        secureZero(ss, ssSize);
        free(ss);
        throwKazKemException(env, -2, "Failed to create shared secret array");
        return nullptr;
    }

    env->SetByteArrayRegion(sharedSecret, 0, ssLen, (jbyte *)ss);

    // Secure cleanup
    secureZero(ss, ssSize);
    free(ss);

    return sharedSecret;
}

// ============================================================================
// Version
// ============================================================================

JNIEXPORT jstring JNICALL
Java_com_antrapol_kaz_kem_KazKemNative_nativeVersion(JNIEnv *env, jclass clazz) {
    const char *version = kaz_kem_version();
    return env->NewStringUTF(version ? version : "unknown");
}

} // extern "C"
