package com.clpkc.kgc.crypto;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithID;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.PlainDSAEncoding;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.math.ec.ECPoint;

/**
 * CL-PKC 协议密码学原语（国密 SM2/SM3，隐式证书方案，无状态）。
 *
 * <p>WA=wG+UA，tA=(w+λ·ms) mod n，dA=tA+ua，PA=WA+λ·Ppub；
 * HA=SM3(len2B(id)‖id‖a‖b‖Gx‖Gy‖PpubX‖PpubY)，λ=SM3(WAx‖WAy‖HA)。
 * SM2 公钥加密（C1C3C2 原始拼接）、SM2 数字签名（线上裸 r‖s，64 字节）、HMAC-SM3。</p>
 */
public final class ClpkcCrypto {

    private static final Logger log = LoggerFactory.getLogger(ClpkcCrypto.class);
    /** transcript / KDF 拼接里 ID 的定长字节数（右侧 0x00 补齐）。 */
    private static final int ID_FIXED_LEN = 32;

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
    // SM2 签名 / 验签（线上裸 r‖s 64 字节；id 作 ZA 用户标识；transcript 绑 nonce）
    // ------------------------------------------------------------------

    /** 发起方（桩）签名：transcript = R_B ‖ ID_B ‖ W_B ‖ nonce（发起时尚无 R_A，只签自己的）。 */
    public String signInitiator(byte[] rB, String idB, byte[] wB, String nonce, BigInteger fullPrivate) {
        return sm2Sign(transcriptInitiator(rB, idB, wB, nonce), idB, fullPrivate);
    }

    public boolean verifyInitiator(byte[] rB, String idB, byte[] wB, String nonce, String sigHex, String fullPublicHex) {
        return sm2Verify(transcriptInitiator(rB, idB, wB, nonce), idB, sigHex, fullPublicHex);
    }

    /** 响应方（云）签名：transcript = R_A ‖ R_B ‖ ID_A ‖ W_A ‖ nonce（已收到 R_B，绑双方临时公钥）。 */
    public String signResponder(byte[] rA, byte[] rB, String idA, byte[] wA, String nonce, BigInteger fullPrivate) {
        return sm2Sign(transcriptResponder(rA, rB, idA, wA, nonce), idA, fullPrivate);
    }

    public boolean verifyResponder(byte[] rA, byte[] rB, String idA, byte[] wA, String nonce, String sigHex, String fullPublicHex) {
        return sm2Verify(transcriptResponder(rA, rB, idA, wA, nonce), idA, sigHex, fullPublicHex);
    }

    private String sm2Sign(byte[] msg, String id, BigInteger fullPrivate) {
        try {
            SM2Signer signer = new SM2Signer(PlainDSAEncoding.INSTANCE);  // 裸 r‖s 64 字节
            signer.init(true, new ParametersWithID(new ParametersWithRandom(
                new ECPrivateKeyParameters(fullPrivate, EcCurve.DOMAIN), random),
                id.getBytes(StandardCharsets.UTF_8)));
            signer.update(msg, 0, msg.length);
            return Hex.encode(signer.generateSignature());
        } catch (Exception e) {
            throw new IllegalStateException("SM2 sign failed", e);
        }
    }

    private boolean sm2Verify(byte[] msg, String id, String sigHex, String fullPublicHex) {
        try {
            ECPoint pa = curve.pointFromHex(fullPublicHex);
            SM2Signer signer = new SM2Signer(PlainDSAEncoding.INSTANCE);  // 裸 r‖s 64 字节
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

    /** SK = SM3( Sx ‖ R_A ‖ R_B ‖ ID_A ‖ ID_B ‖ nonce )，全定长字段直拼、单次 SM3 出 32 字节。 */
    public String deriveSessionKey(BigInteger ephemeralScalar, String peerPointHex,
                                   byte[] ra, byte[] rb, String idA, String idB, String nonce) {
        ECPoint shared = curve.multiply(curve.pointFromHex(peerPointHex), ephemeralScalar);
        byte[] sharedX = curve.toFixed(shared.normalize().getAffineXCoord().toBigInteger(), EcCurve.SCALAR_LEN);
        byte[] digest = EcCurve.sm3(concat(sharedX, ra, rb,
            fixedId(idA), fixedId(idB), nonce.getBytes(StandardCharsets.UTF_8)));
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

    /** 发起方 transcript：R_B ‖ ID_B ‖ W_B ‖ nonce（全定长字段直拼，无长度前缀）。 */
    private byte[] transcriptInitiator(byte[] rB, String idB, byte[] wB, String nonce) {
        return concat(rB, fixedId(idB), wB, nonce.getBytes(StandardCharsets.UTF_8));
    }

    /** 响应方 transcript：R_A ‖ R_B ‖ ID_A ‖ W_A ‖ nonce（全定长字段直拼，无长度前缀）。 */
    private byte[] transcriptResponder(byte[] rA, byte[] rB, String idA, byte[] wA, String nonce) {
        return concat(rA, rB, fixedId(idA), wA, nonce.getBytes(StandardCharsets.UTF_8));
    }

    /** ID 定长编码：UTF-8 取 {@value #ID_FIXED_LEN} 字节，右侧 0x00 补齐；超长截断并告警。 */
    private byte[] fixedId(String id) {
        byte[] raw = id.getBytes(StandardCharsets.UTF_8);
        byte[] out = new byte[ID_FIXED_LEN];
        int n = Math.min(raw.length, ID_FIXED_LEN);
        if (raw.length > ID_FIXED_LEN) {
            log.warn("ID 超过 {} 字节，已截断用于 transcript/KDF: {}", ID_FIXED_LEN, id);
        }
        System.arraycopy(raw, 0, out, 0, n);
        return out;
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
