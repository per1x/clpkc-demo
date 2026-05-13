package demo.clpkc.kgc;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public final class ClpCrypto {
    private final Secp256r1 curve = new Secp256r1();
    private final BigInteger masterSecret;
    private final Secp256r1.Point masterPublic;

    public ClpCrypto() {
        this.masterSecret = curve.randomScalar();
        this.masterPublic = curve.multiply(Secp256r1.G, masterSecret);
    }

    public BigInteger getMasterSecret() {
        return masterSecret;
    }

    public String getMasterPublicHex() {
        return Hexs.encode(curve.encode(masterPublic));
    }

    public BigInteger issuePartialPrivate(String id, String publicKeyHex) {
        BigInteger h = h1(id, publicKeyHex);
        return masterSecret.multiply(h).mod(Secp256r1.N);
    }

    public BigInteger h1(String id, String publicKeyHex) {
        return hashToScalar(id.getBytes(StandardCharsets.UTF_8), Hexs.decode(publicKeyHex));
    }

    public String eciesEncrypt(byte[] plaintext, String recipientPublicKeyHex) {
        try {
            byte[] recipientKeyBytes = Hexs.decode(recipientPublicKeyHex);
            Secp256r1.Point recipientKey = curve.decode(recipientKeyBytes);

            BigInteger r = curve.randomScalar();
            Secp256r1.Point R = curve.multiply(Secp256r1.G, r);
            byte[] R_bytes = curve.encode(R);

            Secp256r1.Point S = curve.multiply(recipientKey, r);

            byte[] sharedX = curve.toFixed(S.x(), 32);
            byte[] aesKey = sha256(sharedX);

            byte[] iv = new byte[12];
            new SecureRandom().nextBytes(iv);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
            SecretKeySpec keySpec = new SecretKeySpec(aesKey, "AES");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
            byte[] ciphertextWithTag = cipher.doFinal(plaintext);

            byte[] result = new byte[65 + 12 + ciphertextWithTag.length];
            System.arraycopy(R_bytes, 0, result, 0, 65);
            System.arraycopy(iv, 0, result, 65, 12);
            System.arraycopy(ciphertextWithTag, 0, result, 77, ciphertextWithTag.length);

            return Hexs.encode(result);
        } catch (Exception e) {
            throw new IllegalStateException("ECIES encryption failed", e);
        }
    }

    byte[] sha256(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return md.digest(data);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private BigInteger hashToScalar(byte[]... parts) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            for (byte[] part : parts) {
                md.update(part);
            }
            BigInteger v = new BigInteger(1, md.digest()).mod(Secp256r1.N);
            return v.equals(BigInteger.ZERO) ? BigInteger.ONE : v;
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
