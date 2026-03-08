package com.antrapol.wallet.crypto

import com.antrapol.kaz.sign.SecurityLevel
import java.io.ByteArrayOutputStream

/**
 * Builder for PKCS#10 Certificate Signing Requests (CSRs) with KAZ-SIGN.
 * Implements ASN.1/DER encoding for CSR generation.
 * Supports all KAZ-SIGN security levels (128, 192, 256).
 */
class CsrBuilder(
    private val cryptoProvider: KazSignCryptoProvider
) {
    companion object {
        // KAZ-SIGN OID components: 2.16.458.1.1.1.1.{level}
        // 2.16.458 = 0x60 0x86 0x83 0x4A (Malaysia arc)
        // .1.1.1.1 = 0x01 0x01 0x01 0x01
        private val KAZ_SIGN_OID_BASE = byteArrayOf(
            0x60.toByte(), 0x86.toByte(), 0x83.toByte(), 0x4A.toByte(),
            0x01, 0x01, 0x01, 0x01
        )

        // X.500 OIDs
        private val OID_COMMON_NAME = byteArrayOf(0x55, 0x04, 0x03)
        private val OID_SERIAL_NUMBER = byteArrayOf(0x55, 0x04, 0x05)
        private val OID_COUNTRY = byteArrayOf(0x55, 0x04, 0x06)
        private val OID_ORGANIZATION = byteArrayOf(0x55, 0x04, 0x0A)

        /**
         * Get the OID bytes for a specific security level.
         */
        fun getOidForLevel(level: SecurityLevel): ByteArray {
            val levelByte = when (level) {
                SecurityLevel.LEVEL_128 -> 0x01.toByte()
                SecurityLevel.LEVEL_192 -> 0x02.toByte()
                SecurityLevel.LEVEL_256 -> 0x03.toByte()
            }
            return KAZ_SIGN_OID_BASE + levelByte
        }
    }

    private val algorithmOid: ByteArray = getOidForLevel(cryptoProvider.level)

    /**
     * Builds a CSR for the given subject and keypair.
     * @param commonName Subject's common name (full name)
     * @param serialNumber Subject's serial number (e.g., MyKad number)
     * @param country Country code (default: MY)
     * @param organization Organization name (optional)
     * @param keyPair The KAZ-SIGN keypair
     * @return CSR in DER format
     */
    fun buildCsr(
        commonName: String,
        serialNumber: String,
        country: String = "MY",
        organization: String? = null,
        keyPair: KazSignKeyPair
    ): ByteArray {
        // Build CertificationRequestInfo (TBS - To Be Signed)
        val tbsData = buildCertificationRequestInfo(
            commonName = commonName,
            serialNumber = serialNumber,
            country = country,
            organization = organization,
            publicKey = keyPair.publicKey
        )

        // Sign TBS with secret key
        val signature = cryptoProvider.sign(keyPair.secretKey, tbsData)

        // Assemble final CSR
        return assembleCsr(tbsData, signature)
    }

    /**
     * Builds a CSR and returns it as PEM-encoded string.
     */
    fun buildCsrPem(
        commonName: String,
        serialNumber: String,
        country: String = "MY",
        organization: String? = null,
        keyPair: KazSignKeyPair
    ): String {
        val der = buildCsr(commonName, serialNumber, country, organization, keyPair)
        val base64 = android.util.Base64.encodeToString(der, android.util.Base64.NO_WRAP)
        return buildString {
            appendLine("-----BEGIN CERTIFICATE REQUEST-----")
            base64.chunked(64).forEach { appendLine(it) }
            appendLine("-----END CERTIFICATE REQUEST-----")
        }
    }

    private fun buildCertificationRequestInfo(
        commonName: String,
        serialNumber: String,
        country: String,
        organization: String?,
        publicKey: ByteArray
    ): ByteArray {
        val builder = DerBuilder()

        builder.beginSequence()

        // Version INTEGER (0 for v1)
        builder.writeInteger(0)

        // Subject Name
        builder.writeRaw(buildSubjectName(commonName, serialNumber, country, organization))

        // SubjectPublicKeyInfo
        builder.writeRaw(buildSubjectPublicKeyInfo(publicKey))

        // Attributes [0] (empty for now)
        builder.writeContextTag(0, byteArrayOf())

        builder.endSequence()

        return builder.build()
    }

    private fun buildSubjectName(
        commonName: String,
        serialNumber: String,
        country: String,
        organization: String?
    ): ByteArray {
        val builder = DerBuilder()
        builder.beginSequence()

        // Country
        builder.writeRaw(buildRdn(OID_COUNTRY, country))

        // Organization (if provided)
        if (!organization.isNullOrBlank()) {
            builder.writeRaw(buildRdn(OID_ORGANIZATION, organization))
        }

        // Common Name
        builder.writeRaw(buildRdn(OID_COMMON_NAME, commonName))

        // Serial Number (e.g., MyKad)
        builder.writeRaw(buildRdn(OID_SERIAL_NUMBER, serialNumber))

        builder.endSequence()
        return builder.build()
    }

    private fun buildRdn(oid: ByteArray, value: String): ByteArray {
        val builder = DerBuilder()
        builder.beginSet()
        builder.beginSequence()
        builder.writeOid(oid)
        builder.writeUtf8String(value)
        builder.endSequence()
        builder.endSet()
        return builder.build()
    }

    private fun buildSubjectPublicKeyInfo(publicKey: ByteArray): ByteArray {
        val builder = DerBuilder()
        builder.beginSequence()
        builder.writeRaw(buildAlgorithmIdentifier())
        builder.writeBitString(publicKey)
        builder.endSequence()
        return builder.build()
    }

    private fun buildAlgorithmIdentifier(): ByteArray {
        val builder = DerBuilder()
        builder.beginSequence()
        builder.writeOid(algorithmOid)
        builder.endSequence()
        return builder.build()
    }

    private fun assembleCsr(tbsData: ByteArray, signature: ByteArray): ByteArray {
        val builder = DerBuilder()
        builder.beginSequence()

        // CertificationRequestInfo
        builder.writeRaw(tbsData)

        // SignatureAlgorithm
        builder.writeRaw(buildAlgorithmIdentifier())

        // Signature
        builder.writeBitString(signature)

        builder.endSequence()
        return builder.build()
    }

    private val KazSignCryptoProvider.level: SecurityLevel
        get() = when (algorithmName) {
            "KAZ-SIGN-128" -> SecurityLevel.LEVEL_128
            "KAZ-SIGN-192" -> SecurityLevel.LEVEL_192
            "KAZ-SIGN-256" -> SecurityLevel.LEVEL_256
            else -> SecurityLevel.LEVEL_256
        }
}

/**
 * Simple DER builder for constructing ASN.1 structures.
 */
internal class DerBuilder {
    private val data = ByteArrayOutputStream()
    private val sequenceStarts = mutableListOf<Int>()

    fun beginSequence() {
        data.write(0x30) // SEQUENCE tag
        sequenceStarts.add(data.size())
        data.write(0x00) // Placeholder for length
    }

    fun endSequence() {
        finalizeContainer()
    }

    fun beginSet() {
        data.write(0x31) // SET tag
        sequenceStarts.add(data.size())
        data.write(0x00) // Placeholder
    }

    fun endSet() {
        finalizeContainer()
    }

    fun writeInteger(value: Int) {
        data.write(0x02) // INTEGER tag
        if (value == 0) {
            data.write(0x01)
            data.write(0x00)
        } else {
            val bytes = intToBytes(value)
            writeLength(bytes.size)
            data.write(bytes)
        }
    }

    fun writeOid(oid: ByteArray) {
        data.write(0x06) // OID tag
        writeLength(oid.size)
        data.write(oid)
    }

    fun writeUtf8String(value: String) {
        val bytes = value.toByteArray(Charsets.UTF_8)
        data.write(0x0C) // UTF8String tag
        writeLength(bytes.size)
        data.write(bytes)
    }

    fun writeBitString(content: ByteArray) {
        data.write(0x03) // BIT STRING tag
        writeLength(content.size + 1)
        data.write(0x00) // No unused bits
        data.write(content)
    }

    fun writeContextTag(tag: Int, content: ByteArray) {
        data.write(0xA0 or tag) // Context tag
        writeLength(content.size)
        data.write(content)
    }

    fun writeRaw(bytes: ByteArray) {
        data.write(bytes)
    }

    fun build(): ByteArray = data.toByteArray()

    private fun writeLength(length: Int) {
        when {
            length < 128 -> data.write(length)
            length < 256 -> {
                data.write(0x81)
                data.write(length)
            }
            length < 65536 -> {
                data.write(0x82)
                data.write(length shr 8)
                data.write(length and 0xFF)
            }
            else -> {
                data.write(0x83)
                data.write(length shr 16)
                data.write((length shr 8) and 0xFF)
                data.write(length and 0xFF)
            }
        }
    }

    private fun finalizeContainer() {
        if (sequenceStarts.isEmpty()) return

        val startIndex = sequenceStarts.removeLast()
        val currentData = data.toByteArray()
        val contentLength = currentData.size - startIndex - 1

        // Rebuild with correct length
        data.reset()
        data.write(currentData, 0, startIndex)

        if (contentLength < 128) {
            data.write(contentLength)
        } else if (contentLength < 256) {
            data.write(0x81)
            data.write(contentLength)
        } else if (contentLength < 65536) {
            data.write(0x82)
            data.write(contentLength shr 8)
            data.write(contentLength and 0xFF)
        }

        data.write(currentData, startIndex + 1, contentLength)
    }

    private fun intToBytes(value: Int): ByteArray {
        if (value == 0) return byteArrayOf(0)

        val result = mutableListOf<Byte>()
        var v = value
        while (v > 0) {
            result.add(0, (v and 0xFF).toByte())
            v = v shr 8
        }

        // Add leading zero if high bit is set (to ensure positive interpretation)
        if ((result[0].toInt() and 0x80) != 0) {
            result.add(0, 0)
        }

        return result.toByteArray()
    }
}
