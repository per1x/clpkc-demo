package com.clpkc.core;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.math.ec.ECPoint;

import com.clpkc.core.util.Hex;

/**
 * CL-PKC 协议密码学原语（无状态）。
 *
 * <p>相对原 Demo 的改动：</p>
 * <ul>
 *   <li>底层曲线运算改用 BouncyCastle（见 {@link EcCurve}）。</li>
 *   <li>KGC 主私钥不再在本类内随机生成，而是<b>由调用方从配置注入</b>，
 *       本类保持无状态、可复用、线程安全。</li>
 *   <li>签名 transcript 与会话密钥派生<b>去除时间戳</b>，改用握手阶段
 *       服务端下发的一次性 {@code nonce} 做防重放绑定。</li>
 * </ul>
 *
 * <p>与 C++（充电桩）互操作的字节级约定：点为 SEC1 非压缩；H2 = SHA256(X32||Y32) mod N；
 * Schnorr 挑战 e = SHA256(R65 || transcript) mod N；transcript 为 4 段
 * {@code len(2B BE)||bytes}，依次 (ra, id, wb, nonce)；会话密钥
 * = SHA256(sharedX32 || ra || rb || idA || idB || nonce)。</p>
 */
public final class ClpkcCrypto {

    /** ECIES 密文布局：R(65) || IV(12) || ciphertext+tag。 */
    private static final int ECIES_R_LEN = 65;
    private static final int ECIES_IV_LEN = 12;
    private static final int GCM_TAG_BITS = 128;

    private final EcCurve curve;
    private final SecureRandom random;

    public ClpkcCrypto() {
        this(new SecureRandom());
    }

    public ClpkcCrypto(SecureRandom random) {
        this.random = random;
        this.curve = new EcCurve(random);
    }

    public EcCurve curve() {
        return curve;
    }

    /** Schnorr 签名 (R, s)。 */
    public record Signature(String rHex, String sHex) {
        public String toHex() {
            return rHex + sHex;
        }
    }

    /** 静态密钥材料 (x_i, P_i)。 */
    public record KeyMaterial(BigInteger secretScalar, String publicKeyHex) {
    }

    /** 完整密钥 (sk_i, Y_i)。 */
    public record FullKey(BigInteger privateScalar, String derivedPublicHex) {
    }

    // ------------------------------------------------------------------
    // 密钥生成 / 组合
    // ------------------------------------------------------------------

    /** 生成静态密钥对 (x_i, P_i = x_i·G)。 */
    public KeyMaterial generateStaticKey() {
        BigInteger x = curve.randomScalar();
        return new KeyMaterial(x, Hex.encode(curve.encode(curve.basePointMul(x))));
    }

    /** KGC 主公钥 Ppub = s·G 的十六进制 SEC1 编码。 */
    public String masterPublicHex(BigInteger masterSecret) {
        return Hex.encode(curve.encode(curve.basePointMul(masterSecret)));
    }

    /**
     * KGC 颁发部分私钥点 D_i = s · H1(ID || P_i)。
     *
     * @param masterSecret  KGC 主私钥 s（配置注入）
     * @param id            申请方标识
     * @param publicKeyHex  申请方静态公钥 P_i
     * @return D_i 的 65 字节 SEC1 编码
     */
    public byte[] issuePartialPrivate(BigInteger masterSecret, String id, String publicKeyHex) {
        ECPoint qi = curve.hashToCurve(id.getBytes(StandardCharsets.UTF_8), Hex.decode(publicKeyHex));
        return curve.encode(curve.multiply(qi, masterSecret));
    }

    /** H2：点 → 标量 d = SHA256(X32||Y32) mod N（0 → 1）。 */
    public BigInteger hashPointToScalar(ECPoint p) {
        ECPoint np = p.normalize();
        byte[] x = curve.toFixed(np.getAffineXCoord().toBigInteger(), EcCurve.SCALAR_LEN);
        byte[] y = curve.toFixed(np.getAffineYCoord().toBigInteger(), EcCurve.SCALAR_LEN);
        byte[] combined = concat(x, y);
        BigInteger v = new BigInteger(1, EcCurve.sha256(combined)).mod(EcCurve.N);
        return v.signum() == 0 ? BigInteger.ONE : v;
    }

    /**
     * 组合完整密钥：ECIES 解密 D_i → d_i = H2(D_i) → sk_i = x_i + d_i；Y_i = d_i·G。
     */
    public FullKey composeFullKey(BigInteger secret, String encryptedPartialHex) {
        byte[] partial = eciesDecrypt(encryptedPartialHex, secret);
        ECPoint di = curve.decode(partial);
        BigInteger d = hashPointToScalar(di);
        BigInteger sk = secret.add(d).mod(EcCurve.N);
        String yHex = Hex.encode(curve.encode(curve.basePointMul(d)));
        return new FullKey(sk, yHex);
    }

    /** 完整公钥 PK_i = P_i + Y_i。 */
    public String deriveFullPublic(String publicKeyHex, String derivedPublicHex) {
        ECPoint pi = curve.decode(Hex.decode(publicKeyHex));
        ECPoint yi = curve.decode(Hex.decode(derivedPublicHex));
        return Hex.encode(curve.encode(curve.add(pi, yi)));
    }

    // ------------------------------------------------------------------
    // ECIES
    // ------------------------------------------------------------------

    /**
     * ECIES 加密：R=r·G；S=r·P；AES-256-GCM(key=SHA256(x(S)))。
     *
     * @return R(65) || IV(12) || ciphertext+tag 的十六进制
     */
    public String eciesEncrypt(byte[] plaintext, String recipientPublicKeyHex) {
        try {
            ECPoint recipient = curve.decode(Hex.decode(recipientPublicKeyHex));
            BigInteger r = curve.randomScalar();
            byte[] rEnc = curve.encode(curve.basePointMul(r));
            ECPoint s = curve.multiply(recipient, r);
            byte[] aesKey = EcCurve.sha256(curve.affineX(s));

            byte[] iv = new byte[ECIES_IV_LEN];
            random.nextBytes(iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(aesKey, "AES"),
                new GCMParameterSpec(GCM_TAG_BITS, iv));
            byte[] ct = cipher.doFinal(plaintext);
            return Hex.encode(concat(rEnc, iv, ct));
        } catch (Exception e) {
            throw new IllegalStateException("ECIES encryption failed", e);
        }
    }

    /** ECIES 解密。 */
    public byte[] eciesDecrypt(String encryptedBlobHex, BigInteger secretScalar) {
        try {
            byte[] blob = Hex.decode(encryptedBlobHex);
            if (blob.length < ECIES_R_LEN + ECIES_IV_LEN + 16) {
                throw new IllegalArgumentException("invalid ECIES ciphertext length");
            }
            byte[] rEnc = slice(blob, 0, ECIES_R_LEN);
            byte[] iv = slice(blob, ECIES_R_LEN, ECIES_R_LEN + ECIES_IV_LEN);
            byte[] ct = slice(blob, ECIES_R_LEN + ECIES_IV_LEN, blob.length);

            ECPoint rPoint = curve.decode(rEnc);
            ECPoint s = curve.multiply(rPoint, secretScalar);
            byte[] aesKey = EcCurve.sha256(curve.affineX(s));

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(aesKey, "AES"),
                new GCMParameterSpec(GCM_TAG_BITS, iv));
            return cipher.doFinal(ct);
        } catch (Exception e) {
            throw new IllegalStateException("ECIES decryption failed", e);
        }
    }

    // ------------------------------------------------------------------
    // Schnorr 签名 / 验签（transcript 绑定 nonce，无时间戳）
    // ------------------------------------------------------------------

    public Signature sign(byte[] ra, String id, byte[] wb, String nonce, BigInteger fullPrivate) {
        byte[] transcript = transcript(ra, id, wb, nonce);
        BigInteger k = curve.randomScalar();
        byte[] rEnc = curve.encode(curve.basePointMul(k));
        BigInteger e = challenge(rEnc, transcript);
        BigInteger s = k.add(e.multiply(fullPrivate)).mod(EcCurve.N);
        return new Signature(Hex.encode(rEnc), Hex.encode(curve.toFixed(s, EcCurve.SCALAR_LEN)));
    }

    public boolean verify(byte[] ra, String id, byte[] wb, String nonce, String sigHex, String fullPublicHex) {
        byte[] sig = Hex.decode(sigHex);
        if (sig.length != EcCurve.POINT_LEN + EcCurve.SCALAR_LEN) {
            return false;
        }
        byte[] rEnc = slice(sig, 0, EcCurve.POINT_LEN);
        BigInteger s = new BigInteger(1, slice(sig, EcCurve.POINT_LEN, sig.length));
        byte[] transcript = transcript(ra, id, wb, nonce);
        BigInteger e = challenge(rEnc, transcript);
        try {
            ECPoint left = curve.basePointMul(s);
            ECPoint rPoint = curve.decode(rEnc);
            ECPoint pk = curve.decode(Hex.decode(fullPublicHex));
            ECPoint right = curve.add(rPoint, curve.multiply(pk, e));
            return !left.isInfinity() && left.equals(right);
        } catch (RuntimeException ex) {
            return false;
        }
    }

    // ------------------------------------------------------------------
    // 会话密钥 / HMAC
    // ------------------------------------------------------------------

    /** SK = SHA256(x(a·B) || ra || rb || idA || idB || nonce)。 */
    public String deriveSessionKey(BigInteger ephemeralScalar, byte[] peerPoint,
                                   byte[] ra, byte[] rb, String idA, String idB, String nonce) {
        ECPoint shared = curve.multiply(curve.decode(peerPoint), ephemeralScalar);
        byte[] sharedX = curve.affineX(shared);
        byte[] digest = EcCurve.sha256(concat(sharedX, ra, rb,
            idA.getBytes(StandardCharsets.UTF_8), idB.getBytes(StandardCharsets.UTF_8),
            nonce.getBytes(StandardCharsets.UTF_8)));
        return Hex.encode(digest);
    }

    public byte[] hmac(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data);
        } catch (Exception e) {
            throw new IllegalStateException("HMAC failed", e);
        }
    }

    // ------------------------------------------------------------------
    // 内部辅助
    // ------------------------------------------------------------------

    /** 挑战 e = SHA256(R || transcript) mod N（0 → 1）。 */
    private BigInteger challenge(byte[] rEnc, byte[] transcript) {
        BigInteger e = new BigInteger(1, EcCurve.sha256(concat(rEnc, transcript))).mod(EcCurve.N);
        return e.signum() == 0 ? BigInteger.ONE : e;
    }

    /** transcript = len(2B BE)||bytes ×4，依次 (ra, id, wb, nonce)。 */
    private byte[] transcript(byte[] ra, String id, byte[] wb, String nonce) {
        byte[] idBytes = id.getBytes(StandardCharsets.UTF_8);
        byte[] nonceBytes = nonce.getBytes(StandardCharsets.UTF_8);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        appendField(out, ra);
        appendField(out, idBytes);
        appendField(out, wb);
        appendField(out, nonceBytes);
        return out.toByteArray();
    }

    private void appendField(ByteArrayOutputStream out, byte[] field) {
        out.write((field.length >>> 8) & 0xff);
        out.write(field.length & 0xff);
        out.write(field, 0, field.length);
    }

    private static byte[] concat(byte[]... parts) {
        int total = 0;
        for (byte[] p : parts) {
            total += p.length;
        }
        byte[] out = new byte[total];
        int pos = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, pos, p.length);
            pos += p.length;
        }
        return out;
    }

    private static byte[] slice(byte[] src, int from, int to) {
        byte[] out = new byte[to - from];
        System.arraycopy(src, from, out, 0, to - from);
        return out;
    }
}
