/*
 * Java-side interop test: KAZ-SIGN v2.0
 *
 * Simulates SSDID registry flow:
 *   1. Read C-generated pk + signature from stdin, verify
 *   2. Generate own keypair, sign same payload, output for C to verify
 *
 * Usage:
 *   java -cp <classpath> JavaSign verify <level>     # Read from stdin, verify C sig
 *   java -cp <classpath> JavaSign generate <level>    # Generate + sign, output hex
 */

import java.io.*;
import java.math.BigInteger;
import java.util.*;

import com.antrapol.kaz.core.KAZCoreException;
import com.antrapol.kaz.core.sign.*;

public class JavaSign {

    static final String DID_DOCUMENT_PAYLOAD =
        "{\"@context\":[\"https://www.w3.org/ns/did/v1\"]," +
        "\"id\":\"did:ssdid:test-interop-12345\"," +
        "\"verificationMethod\":[{\"controller\":\"did:ssdid:test-interop-12345\"," +
        "\"id\":\"did:ssdid:test-interop-12345#key-1\"," +
        "\"publicKeyMultibase\":\"uPLACEHOLDER\"," +
        "\"type\":\"KazSignVerificationKey2024\"}]}";

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("Usage: JavaSign <generate|verify> <128|192|256>");
            System.exit(1);
        }

        String command = args[0];
        int level = Integer.parseInt(args[1]);

        if ("generate".equals(command)) {
            doGenerate(level);
        } else if ("verify".equals(command)) {
            doVerify(level);
        } else {
            System.err.println("Unknown command: " + command);
            System.exit(1);
        }
    }

    static void doGenerate(int level) throws Exception {
        int idx = levelIndex(level);

        // Generate keypair
        KeyPair kp = KAZSIGNKeyGenerator.generateKeyPair(level);
        PublicKey pk = kp.getPublicKey();
        PrivateKey sk = kp.getPrivateKey();

        // Sign the DID document payload
        byte[] msg = DID_DOCUMENT_PAYLOAD.getBytes("UTF-8");
        SignaturePair sigPair = KAZSIGNSigner.sign(msg, sk);
        Signature sig = sigPair.getSignature();

        // Self-verify
        boolean selfOk = KAZSIGNVerifier.verify(msg, sigPair, pk);
        System.err.println("Java: Self-verification: " + (selfOk ? "PASS" : "FAIL"));

        // Output as hex
        System.out.println("level=" + level);
        System.out.println("pk=" + toFixedHex(pk.v, SystemParameters.SIGN_VBYTES[idx]));
        System.out.println("sk_s=" + toFixedHex(sk.s, SystemParameters.SIGN_SBYTES[idx]));
        System.out.println("sk_t=" + toFixedHex(sk.t, SystemParameters.SIGN_TBYTES[idx]));
        System.out.println("sig_s1=" + toFixedHex(sig.s1, SystemParameters.SIGN_S1BYTES[idx]));
        System.out.println("sig_s2=" + toFixedHex(sig.s2, SystemParameters.SIGN_S2BYTES[idx]));
        System.out.println("sig_s3=" + toFixedHex(sig.s3, SystemParameters.SIGN_S3BYTES[idx]));
        System.out.println("msg=" + DID_DOCUMENT_PAYLOAD);
        System.out.println("status=ok");

        System.err.println("Java: Generated level-" + level + " keypair and signature");
    }

    static void doVerify(int level) throws Exception {
        int idx = levelIndex(level);
        Map<String, String> data = readHexLines();

        // Parse public key
        byte[] pkBytes = hexToBytes(data.get("pk"));
        BigInteger v = new BigInteger(1, pkBytes);
        PublicKey pk = new PublicKey(v, level);

        // Parse signature components
        BigInteger s1 = new BigInteger(1, hexToBytes(data.get("sig_s1")));
        BigInteger s2 = new BigInteger(1, hexToBytes(data.get("sig_s2")));
        BigInteger s3 = new BigInteger(1, hexToBytes(data.get("sig_s3")));
        SignaturePair sigPair = new SignaturePair(new Signature(s1, s2, s3));

        // Parse message
        byte[] msg = data.get("msg").getBytes("UTF-8");

        System.err.println("Java: Verifying C-generated signature (level " + level + ")");

        boolean ok = KAZSIGNVerifier.verify(msg, sigPair, pk);
        System.out.println("verify=" + (ok ? "PASS" : "FAIL"));
        System.err.println("Java: Verification of C signature: " + (ok ? "PASS" : "FAIL"));

        if (!ok) System.exit(1);
    }

    // -- Helpers --

    static String toFixedHex(BigInteger val, int byteLen) {
        byte[] raw = val.toByteArray();
        byte[] fixed = new byte[byteLen];
        if (raw.length > byteLen) {
            // Strip leading zero byte from BigInteger
            if (raw.length == byteLen + 1 && raw[0] == 0) {
                System.arraycopy(raw, 1, fixed, 0, byteLen);
            } else {
                throw new RuntimeException("Value too large: " + raw.length + " > " + byteLen);
            }
        } else {
            // Left-pad with zeros
            System.arraycopy(raw, 0, fixed, byteLen - raw.length, raw.length);
        }
        StringBuilder sb = new StringBuilder();
        for (byte b : fixed) sb.append(String.format("%02x", b & 0xff));
        return sb.toString();
    }

    static byte[] hexToBytes(String hex) {
        if (hex == null) return new byte[0];
        int len = hex.length() / 2;
        byte[] out = new byte[len];
        for (int i = 0; i < len; i++) {
            out[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
        }
        return out;
    }

    static Map<String, String> readHexLines() throws Exception {
        Map<String, String> map = new HashMap<>();
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        String line;
        while ((line = br.readLine()) != null) {
            int eq = line.indexOf('=');
            if (eq > 0) {
                map.put(line.substring(0, eq), line.substring(eq + 1));
            }
        }
        return map;
    }

    static int levelIndex(int level) {
        return switch (level) {
            case 128 -> 0;
            case 192 -> 1;
            case 256 -> 2;
            default -> throw new RuntimeException("Invalid level: " + level);
        };
    }
}
