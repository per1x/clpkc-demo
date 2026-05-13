package demo.clpkc.cloud;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public final class ClpCrypto {
    public record Signature(String rHex, String sHex) {
        public String toHex() {
            return rHex + sHex;
        }
    }

    public record KeyMaterial(BigInteger secretScalar, String publicKeyHex) {
    }

    private final Secp256r1 curve = new Secp256r1();

    public KeyMaterial generateStaticKey() {
        BigInteger x = curve.randomScalar();
        return new KeyMaterial(x, Hexs.encode(curve.encode(curve.multiply(Secp256r1.G, x))));
    }

    public BigInteger composeFullPrivate(BigInteger secret, String partialHex) {
        return secret.add(new BigInteger(1, Hexs.decode(partialHex))).mod(Secp256r1.N);
    }

    public String deriveFullPublic(String id, String publicKeyHex, String masterPublicKeyHex) {
        BigInteger h = h1(id, publicKeyHex);
        Secp256r1.Point p = curve.decode(Hexs.decode(publicKeyHex));
        Secp256r1.Point ppub = curve.decode(Hexs.decode(masterPublicKeyHex));
        Secp256r1.Point full = curve.add(p, curve.multiply(ppub, h));
        return Hexs.encode(curve.encode(full));
    }

    public byte[] eciesDecrypt(String encryptedBlobHex, BigInteger secretScalar) {
        try {
            byte[] blob = Hexs.decode(encryptedBlobHex);

            byte[] R_bytes = Arrays.copyOfRange(blob, 0, 65);
            byte[] iv = Arrays.copyOfRange(blob, 65, 77);
            byte[] ciphertextWithTag = Arrays.copyOfRange(blob, 77, blob.length);

            Secp256r1.Point R = curve.decode(R_bytes);
            Secp256r1.Point S = curve.multiply(R, secretScalar);

            byte[] sharedX = curve.toFixed(S.x(), 32);
            byte[] aesKey = sha256(sharedX);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
            SecretKeySpec keySpec = new SecretKeySpec(aesKey, "AES");
            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);
            return cipher.doFinal(ciphertextWithTag);
        } catch (Exception e) {
            throw new IllegalStateException("ECIES decryption failed", e);
        }
    }

    public BigInteger composeFullPrivateDecrypted(BigInteger secret, String encryptedPartialHex) {
        byte[] partialBytes = eciesDecrypt(encryptedPartialHex, secret);
        BigInteger partialPrivate = new BigInteger(1, partialBytes);
        return secret.add(partialPrivate).mod(Secp256r1.N);
    }

    public Signature sign(byte[] ra, String id, byte[] wb, String t, BigInteger fullPrivate) {
        byte[] transcript = transcript(ra, id, wb, t);
        BigInteger k = curve.randomScalar();
        Secp256r1.Point rPoint = curve.multiply(Secp256r1.G, k);
        byte[] rEncoded = curve.encode(rPoint);
        BigInteger e = hashToScalar(rEncoded, transcript);
        BigInteger s = k.add(e.multiply(fullPrivate)).mod(Secp256r1.N);
        return new Signature(Hexs.encode(rEncoded), Hexs.encode(curve.toFixed(s, 32)));
    }

    public boolean verify(byte[] ra, String id, byte[] wb, String t, String sigHex, String fullPublicHex) {
        byte[] sig = Hexs.decode(sigHex);
        byte[] rEncoded = Arrays.copyOfRange(sig, 0, 65);
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(sig, 65, 97));
        byte[] transcript = transcript(ra, id, wb, t);
        BigInteger e = hashToScalar(rEncoded, transcript);
        Secp256r1.Point left = curve.multiply(Secp256r1.G, s);
        Secp256r1.Point r = curve.decode(rEncoded);
        Secp256r1.Point pk = curve.decode(Hexs.decode(fullPublicHex));
        Secp256r1.Point right = curve.add(r, curve.multiply(pk, e));
        return !left.infinity() && left.x().equals(right.x()) && left.y().equals(right.y());
    }

    public String deriveSessionKey(BigInteger ephemeralScalar, byte[] peerPoint, byte[] ra, byte[] rb, String ida, String idb, String ta, String tb) {
        Secp256r1.Point shared = curve.multiply(curve.decode(peerPoint), ephemeralScalar);
        byte[] sharedX = curve.toFixed(shared.x(), 32);
        return Hexs.encode(hash(sharedX, ra, rb, ida.getBytes(StandardCharsets.UTF_8), idb.getBytes(StandardCharsets.UTF_8),
            ta.getBytes(StandardCharsets.UTF_8), tb.getBytes(StandardCharsets.UTF_8)));
    }

    public byte[] hmac(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public BigInteger h1(String id, String publicKeyHex) {
        return hashToScalar(id.getBytes(StandardCharsets.UTF_8), Hexs.decode(publicKeyHex));
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
        BigInteger v = new BigInteger(1, hash(parts)).mod(Secp256r1.N);
        return v.equals(BigInteger.ZERO) ? BigInteger.ONE : v;
    }

    private byte[] hash(byte[]... parts) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            for (byte[] part : parts) {
                md.update(part);
            }
            return md.digest();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private byte[] transcript(byte[] ra, String id, byte[] wb, String t) {
        return concat(len(ra.length), ra, len(id.getBytes(StandardCharsets.UTF_8).length), id.getBytes(StandardCharsets.UTF_8),
            len(wb.length), wb, len(t.getBytes(StandardCharsets.UTF_8).length), t.getBytes(StandardCharsets.UTF_8));
    }

    private byte[] len(int size) {
        return ByteBuffer.allocate(2).putShort((short) size).array();
    }

    private byte[] concat(byte[]... items) {
        int total = 0;
        for (byte[] item : items) {
            total += item.length;
        }
        byte[] out = new byte[total];
        int off = 0;
        for (byte[] item : items) {
            System.arraycopy(item, 0, out, off, item.length);
            off += item.length;
        }
        return out;
    }
}
