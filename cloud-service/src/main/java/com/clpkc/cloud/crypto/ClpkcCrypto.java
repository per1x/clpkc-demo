package com.clpkc.cloud.crypto;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithID;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.math.ec.ECPoint;

/**
 * CL-PKC 协议密码学原语（国密 SM2/SM3，隐式证书方案，无状态）。
 *
 * <p>WA=wG+UA，tA=(w+λ·ms) mod n，dA=tA+ua，PA=WA+λ·Ppub；
 * HA=SM3(len2B(id)‖id‖a‖b‖Gx‖Gy‖PpubX‖PpubY)，λ=SM3(WAx‖WAy‖HA)。
 * SM2 公钥加密（C1C3C2 原始拼接）、SM2 数字签名（DER）、HMAC-SM3。</p>
 */
public final class ClpkcCrypto {

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

    /** 设备静态密钥材料 (ua, UA)。 */
    public static final class KeyMaterial {
        private final BigInteger secretScalar;
        private final String publicKeyHex;

        public KeyMaterial(BigInteger secretScalar, String publicKeyHex) {
            this.secretScalar = secretScalar;
            this.publicKeyHex = publicKeyHex;
        }

        public BigInteger secretScalar() {
            return secretScalar;
        }

        public String publicKeyHex() {
            return publicKeyHex;
        }
    }

    /** KGC 颁发结果：声明公钥 WA + SM2 加密的部分私钥 tA。 */
    public static final class PartialKey {
        private final String claimedPublicHex;
        private final String encryptedPartialHex;

        public PartialKey(String claimedPublicHex, String encryptedPartialHex) {
            this.claimedPublicHex = claimedPublicHex;
            this.encryptedPartialHex = encryptedPartialHex;
        }

        public String claimedPublicHex() {
            return claimedPublicHex;
        }

        public String encryptedPartialHex() {
            return encryptedPartialHex;
        }
    }

    // ------------------------------------------------------------------
    // 设备侧
    // ------------------------------------------------------------------

    public KeyMaterial generateStaticKey() {
        BigInteger ua = curve.randomScalar();
        return new KeyMaterial(ua, curve.xyHex(curve.basePointMul(ua)));
    }

    /** dA = (tA + ua) mod n（先 SM2 解密出 tA）。 */
    public BigInteger composeFullPrivate(BigInteger uaSecret, String encryptedPartialHex) {
        byte[] taBytes = sm2Decrypt(encryptedPartialHex, uaSecret);
        BigInteger ta = new BigInteger(1, taBytes);
        return uaSecret.add(ta).mod(EcCurve.N);
    }

    /** PA = WA + λ·Ppub。 */
    public String reconstructFullPublicHex(String id, String claimedPublicHex, String masterPublicHex) {
        ECPoint wa = curve.pointFromHex(claimedPublicHex);
        byte[] ha = computeHA(id, masterPublicHex);
        BigInteger lambda = computeLambda(wa, ha);
        ECPoint ppub = curve.pointFromHex(masterPublicHex);
        ECPoint pa = curve.add(wa, curve.multiply(ppub, lambda));
        return curve.xyHex(pa);
    }

    // ------------------------------------------------------------------
    // KGC 侧
    // ------------------------------------------------------------------

    public String masterPublicHex(BigInteger masterSecret) {
        return curve.xyHex(curve.basePointMul(masterSecret));
    }

    public PartialKey issuePartialKey(BigInteger masterSecret, String id, String uaHex) {
        ECPoint ua = curve.pointFromHex(uaHex);
        String ppubHex = masterPublicHex(masterSecret);
        byte[] ha = computeHA(id, ppubHex);
        BigInteger w = curve.randomScalar();
        ECPoint wa = curve.add(curve.basePointMul(w), ua);
        BigInteger lambda = computeLambda(wa, ha);
        BigInteger ta = w.add(lambda.multiply(masterSecret)).mod(EcCurve.N);
        String enc = sm2Encrypt(uaHex, curve.toFixed(ta, EcCurve.SCALAR_LEN));
        return new PartialKey(curve.xyHex(wa), enc);
    }

    // ------------------------------------------------------------------
    // SM2 加密 / 解密（C1C3C2 原始拼接）
    // ------------------------------------------------------------------

    public String sm2Encrypt(String recipientPublicHex, byte[] plaintext) {
        try {
            ECPoint pub = curve.pointFromHex(recipientPublicHex);
            SM2Engine engine = new SM2Engine(new SM3Digest(), SM2Engine.Mode.C1C3C2);
            engine.init(true, new ParametersWithRandom(new ECPublicKeyParameters(pub, EcCurve.DOMAIN), random));
            return Hex.encode(engine.processBlock(plaintext, 0, plaintext.length));
        } catch (Exception e) {
            throw new IllegalStateException("SM2 encryption failed", e);
        }
    }

    public byte[] sm2Decrypt(String encryptedHex, BigInteger secretScalar) {
        try {
            SM2Engine engine = new SM2Engine(new SM3Digest(), SM2Engine.Mode.C1C3C2);
            engine.init(false, new ECPrivateKeyParameters(secretScalar, EcCurve.DOMAIN));
            byte[] blob = Hex.decode(encryptedHex);
            return engine.processBlock(blob, 0, blob.length);
        } catch (Exception e) {
            throw new IllegalStateException("SM2 decryption failed", e);
        }
    }

    // ------------------------------------------------------------------
    // SM2 签名 / 验签（DER；id 作 ZA 用户标识；transcript 绑 nonce）
    // ------------------------------------------------------------------

    public String sign(byte[] ra, String id, byte[] wb, String nonce, BigInteger fullPrivate) {
        try {
            byte[] msg = transcript(ra, id, wb, nonce);
            SM2Signer signer = new SM2Signer();
            signer.init(true, new ParametersWithID(new ParametersWithRandom(
                new ECPrivateKeyParameters(fullPrivate, EcCurve.DOMAIN), random),
                id.getBytes(StandardCharsets.UTF_8)));
            signer.update(msg, 0, msg.length);
            return Hex.encode(signer.generateSignature());
        } catch (Exception e) {
            throw new IllegalStateException("SM2 sign failed", e);
        }
    }

    public boolean verify(byte[] ra, String id, byte[] wb, String nonce, String sigHex, String fullPublicHex) {
        try {
            byte[] msg = transcript(ra, id, wb, nonce);
            ECPoint pa = curve.pointFromHex(fullPublicHex);
            SM2Signer signer = new SM2Signer();
            signer.init(false, new ParametersWithID(
                new ECPublicKeyParameters(pa, EcCurve.DOMAIN), id.getBytes(StandardCharsets.UTF_8)));
            signer.update(msg, 0, msg.length);
            return signer.verifySignature(Hex.decode(sigHex));
        } catch (RuntimeException e) {
            return false;
        }
    }

    // ------------------------------------------------------------------
    // 会话密钥 / HMAC-SM3
    // ------------------------------------------------------------------

    public String deriveSessionKey(BigInteger ephemeralScalar, String peerPointHex,
                                   byte[] ra, byte[] rb, String idA, String idB, String nonce) {
        ECPoint shared = curve.multiply(curve.pointFromHex(peerPointHex), ephemeralScalar);
        byte[] sharedX = curve.toFixed(shared.normalize().getAffineXCoord().toBigInteger(), EcCurve.SCALAR_LEN);
        byte[] digest = EcCurve.sm3(concat(sharedX, ra, rb,
            idA.getBytes(StandardCharsets.UTF_8), idB.getBytes(StandardCharsets.UTF_8),
            nonce.getBytes(StandardCharsets.UTF_8)));
        return Hex.encode(digest);
    }

    public byte[] hmac(byte[] key, byte[] data) {
        HMac mac = new HMac(new SM3Digest());
        mac.init(new KeyParameter(key));
        mac.update(data, 0, data.length);
        byte[] out = new byte[mac.getMacSize()];
        mac.doFinal(out, 0);
        return out;
    }

    // ------------------------------------------------------------------
    // 内部辅助
    // ------------------------------------------------------------------

    private byte[] computeHA(String id, String masterPublicHex) {
        byte[] idBytes = id.getBytes(StandardCharsets.UTF_8);
        int lenBits = idBytes.length * 8;
        byte[] len2B = {(byte) ((lenBits >>> 8) & 0xff), (byte) (lenBits & 0xff)};
        byte[] ppub = Hex.decode(masterPublicHex);
        byte[] px = Arrays.copyOfRange(ppub, 0, 32);
        byte[] py = Arrays.copyOfRange(ppub, 32, 64);
        return EcCurve.sm3(concat(len2B, idBytes,
            EcCurve.A_BYTES, EcCurve.B_BYTES, EcCurve.GX_BYTES, EcCurve.GY_BYTES, px, py));
    }

    private BigInteger computeLambda(ECPoint wa, byte[] ha) {
        byte[] wx = curve.toFixed(wa.normalize().getAffineXCoord().toBigInteger(), EcCurve.SCALAR_LEN);
        byte[] wy = curve.toFixed(wa.normalize().getAffineYCoord().toBigInteger(), EcCurve.SCALAR_LEN);
        return new BigInteger(1, EcCurve.sm3(concat(wx, wy, ha)));
    }

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
}
