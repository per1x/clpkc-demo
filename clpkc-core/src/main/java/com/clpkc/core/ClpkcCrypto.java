package com.clpkc.core;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithID;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.math.ec.ECPoint;

import com.clpkc.core.util.Hex;

/**
 * CL-PKC 协议密码学原语（国密 SM2/SM3，无状态）。
 *
 * <p>国密改造：</p>
 * <ul>
 *   <li>曲线 SM2、哈希 SM3（见 {@link EcCurve}）。</li>
 *   <li>部分私钥加密改用<b>标准 SM2 公钥加密</b>（GM/T 0003，密文 C1C3C2，
 *       统一编码为 <b>ASN.1 DER</b> 以与 OpenSSL 互通）。</li>
 *   <li>无证书签名改用<b>标准 SM2 数字签名</b>（DER 编码，用签名方 ID 做 ZA 绑定）。</li>
 *   <li>挑战-响应 MAC 改用 <b>HMAC-SM3</b>。</li>
 *   <li>KGC 主私钥由调用方从配置注入；签名 transcript 与会话密钥用握手 nonce 绑定（无时间戳）。</li>
 * </ul>
 *
 * <p>与 C++（OpenSSL）互操作约定：SEC1 非压缩点；H2 = SM3(X32||Y32) mod n；SM2 密文/签名
 * 均为 ASN.1 DER；会话密钥 = SM3(x(ECDH) || ra || rb || idA || idB || nonce)。</p>
 */
public final class ClpkcCrypto {

    private static final ECDomainParameters DOMAIN =
        new ECDomainParameters(EcCurve.CURVE, EcCurve.G, EcCurve.N);

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

    /** 静态密钥材料 (x_i, P_i)。 */
    public record KeyMaterial(BigInteger secretScalar, String publicKeyHex) {
    }

    /** 完整密钥 (sk_i, Y_i)。 */
    public record FullKey(BigInteger privateScalar, String derivedPublicHex) {
    }

    // ------------------------------------------------------------------
    // 密钥生成 / 组合
    // ------------------------------------------------------------------

    public KeyMaterial generateStaticKey() {
        BigInteger x = curve.randomScalar();
        return new KeyMaterial(x, Hex.encode(curve.encode(curve.basePointMul(x))));
    }

    public String masterPublicHex(BigInteger masterSecret) {
        return Hex.encode(curve.encode(curve.basePointMul(masterSecret)));
    }

    /** KGC 颁发部分私钥点 D_i = s · H1(ID || P_i)，返回 65 字节 SEC1 编码。 */
    public byte[] issuePartialPrivate(BigInteger masterSecret, String id, String publicKeyHex) {
        ECPoint qi = curve.hashToCurve(id.getBytes(StandardCharsets.UTF_8), Hex.decode(publicKeyHex));
        return curve.encode(curve.multiply(qi, masterSecret));
    }

    /** H2：点 → 标量 d = SM3(X32||Y32) mod N（0 → 1）。 */
    public BigInteger hashPointToScalar(ECPoint p) {
        ECPoint np = p.normalize();
        byte[] x = curve.toFixed(np.getAffineXCoord().toBigInteger(), EcCurve.SCALAR_LEN);
        byte[] y = curve.toFixed(np.getAffineYCoord().toBigInteger(), EcCurve.SCALAR_LEN);
        BigInteger v = new BigInteger(1, EcCurve.sm3(concat(x, y))).mod(EcCurve.N);
        return v.signum() == 0 ? BigInteger.ONE : v;
    }

    /** 组合完整密钥：SM2 解密 D_i → d_i = H2(D_i) → sk_i = x_i + d_i；Y_i = d_i·G。 */
    public FullKey composeFullKey(BigInteger secret, String encryptedPartialHex) {
        byte[] partial = sm2Decrypt(encryptedPartialHex, secret);
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
    // SM2 公钥加密（密文 ASN.1 DER）
    // ------------------------------------------------------------------

    /** SM2 加密，返回 ASN.1 DER 密文的十六进制。 */
    public String sm2Encrypt(byte[] plaintext, String recipientPublicKeyHex) {
        try {
            ECPoint pub = curve.decode(Hex.decode(recipientPublicKeyHex));
            SM2Engine engine = new SM2Engine(new SM3Digest(), SM2Engine.Mode.C1C3C2);
            engine.init(true, new ParametersWithRandom(
                new ECPublicKeyParameters(pub, DOMAIN), random));
            byte[] rawC1C3C2 = engine.processBlock(plaintext, 0, plaintext.length);
            return Hex.encode(rawC1C3C2ToDer(rawC1C3C2));
        } catch (Exception e) {
            throw new IllegalStateException("SM2 encryption failed", e);
        }
    }

    /** SM2 解密（输入 ASN.1 DER 密文的十六进制）。 */
    public byte[] sm2Decrypt(String encryptedDerHex, BigInteger secretScalar) {
        try {
            byte[] rawC1C3C2 = derToRawC1C3C2(Hex.decode(encryptedDerHex));
            SM2Engine engine = new SM2Engine(new SM3Digest(), SM2Engine.Mode.C1C3C2);
            engine.init(false, new ECPrivateKeyParameters(secretScalar, DOMAIN));
            return engine.processBlock(rawC1C3C2, 0, rawC1C3C2.length);
        } catch (Exception e) {
            throw new IllegalStateException("SM2 decryption failed", e);
        }
    }

    // ------------------------------------------------------------------
    // SM2 数字签名（DER 编码；ID 做 ZA 绑定；transcript 绑 nonce）
    // ------------------------------------------------------------------

    /** SM2 签名，返回 DER 签名的十六进制。id 作为 SM2 用户标识参与 ZA。 */
    public String sign(byte[] ra, String id, byte[] wb, String nonce, BigInteger fullPrivate) {
        try {
            byte[] msg = transcript(ra, id, wb, nonce);
            SM2Signer signer = new SM2Signer();
            signer.init(true, new ParametersWithID(new ParametersWithRandom(
                new ECPrivateKeyParameters(fullPrivate, DOMAIN), random),
                id.getBytes(StandardCharsets.UTF_8)));
            signer.update(msg, 0, msg.length);
            return Hex.encode(signer.generateSignature());
        } catch (Exception e) {
            throw new IllegalStateException("SM2 sign failed", e);
        }
    }

    /** SM2 验签。 */
    public boolean verify(byte[] ra, String id, byte[] wb, String nonce, String sigHex, String fullPublicHex) {
        try {
            byte[] msg = transcript(ra, id, wb, nonce);
            ECPoint pk = curve.decode(Hex.decode(fullPublicHex));
            SM2Signer signer = new SM2Signer();
            signer.init(false, new ParametersWithID(
                new ECPublicKeyParameters(pk, DOMAIN), id.getBytes(StandardCharsets.UTF_8)));
            signer.update(msg, 0, msg.length);
            return signer.verifySignature(Hex.decode(sigHex));
        } catch (RuntimeException e) {
            return false;
        }
    }

    // ------------------------------------------------------------------
    // 会话密钥 / HMAC-SM3
    // ------------------------------------------------------------------

    /** SK = SM3(x(a·B) || ra || rb || idA || idB || nonce)。 */
    public String deriveSessionKey(BigInteger ephemeralScalar, byte[] peerPoint,
                                   byte[] ra, byte[] rb, String idA, String idB, String nonce) {
        ECPoint shared = curve.multiply(curve.decode(peerPoint), ephemeralScalar);
        byte[] sharedX = curve.affineX(shared);
        byte[] digest = EcCurve.sm3(concat(sharedX, ra, rb,
            idA.getBytes(StandardCharsets.UTF_8), idB.getBytes(StandardCharsets.UTF_8),
            nonce.getBytes(StandardCharsets.UTF_8)));
        return Hex.encode(digest);
    }

    /** HMAC-SM3。 */
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

    /** BC SM2Engine 的裸 C1C3C2（C1=65B 点, C3=32B, C2=密文）转 OpenSSL ASN.1 DER。 */
    private byte[] rawC1C3C2ToDer(byte[] raw) throws Exception {
        byte[] xb = slice(raw, 1, 33);
        byte[] yb = slice(raw, 33, 65);
        byte[] c3 = slice(raw, 65, 97);
        byte[] c2 = slice(raw, 97, raw.length);
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(new BigInteger(1, xb)));
        v.add(new ASN1Integer(new BigInteger(1, yb)));
        v.add(new DEROctetString(c3));
        v.add(new DEROctetString(c2));
        return new DERSequence(v).getEncoded("DER");
    }

    /** OpenSSL ASN.1 DER 转 BC 需要的裸 C1C3C2。 */
    private byte[] derToRawC1C3C2(byte[] der) {
        ASN1Sequence seq = ASN1Sequence.getInstance(der);
        BigInteger x = ASN1Integer.getInstance(seq.getObjectAt(0)).getPositiveValue();
        BigInteger y = ASN1Integer.getInstance(seq.getObjectAt(1)).getPositiveValue();
        byte[] c3 = ASN1OctetString.getInstance(seq.getObjectAt(2)).getOctets();
        byte[] c2 = ASN1OctetString.getInstance(seq.getObjectAt(3)).getOctets();
        byte[] c1 = new byte[EcCurve.POINT_LEN];
        c1[0] = 0x04;
        System.arraycopy(curve.toFixed(x, EcCurve.SCALAR_LEN), 0, c1, 1, EcCurve.SCALAR_LEN);
        System.arraycopy(curve.toFixed(y, EcCurve.SCALAR_LEN), 0, c1, 1 + EcCurve.SCALAR_LEN, EcCurve.SCALAR_LEN);
        return concat(c1, c3, c2);
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

    static {
        // 确保 BC 的默认安全随机可用（部分环境需要）
        CryptoServicesRegistrar.setSecureRandom(new SecureRandom());
    }
}
