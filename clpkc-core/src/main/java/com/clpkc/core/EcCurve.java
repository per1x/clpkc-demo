package com.clpkc.core;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

/**
 * secp256r1 (NIST P-256) 曲线运算封装。
 *
 * <p>底层改用 <b>BouncyCastle</b> 的经过验证的椭圆曲线实现，替换原 Demo 中
 * 手写、非恒定时间的 {@code Secp256r1}。所有对外暴露的编码/运算都保持与 C++
 * OpenSSL 侧（充电桩）字节级一致：</p>
 * <ul>
 *   <li>点编码：SEC1 非压缩 {@code 0x04 || X(32) || Y(32)}，共 65 字节。</li>
 *   <li>标量编码：32 字节无符号大端。</li>
 *   <li>点解码：{@link ECCurve#decodePoint} 会校验点在曲线上，抵御无效曲线攻击。</li>
 * </ul>
 */
public final class EcCurve {

    private static final X9ECParameters PARAMS = CustomNamedCurves.getByName("secp256r1");

    /** 曲线定义。 */
    public static final ECCurve CURVE = PARAMS.getCurve();
    /** 基点 G。 */
    public static final ECPoint G = PARAMS.getG();
    /** 基点阶 N。 */
    public static final BigInteger N = PARAMS.getN();
    /** 有限域素数 P。 */
    public static final BigInteger P = CURVE.getField().getCharacteristic();
    /** 标量/坐标固定字节长度。 */
    public static final int SCALAR_LEN = 32;
    /** SEC1 非压缩点长度。 */
    public static final int POINT_LEN = 65;

    private final SecureRandom random;

    public EcCurve() {
        this(new SecureRandom());
    }

    public EcCurve(SecureRandom random) {
        this.random = random;
    }

    /**
     * 生成 [1, N-1] 内均匀分布的随机标量（rejection sampling）。
     */
    public BigInteger randomScalar() {
        BigInteger k;
        do {
            k = new BigInteger(N.bitLength(), random);
        } while (k.signum() <= 0 || k.compareTo(N) >= 0);
        return k;
    }

    /** 标量乘法 k·P。 */
    public ECPoint multiply(ECPoint p, BigInteger k) {
        return p.multiply(k.mod(N)).normalize();
    }

    /** 基点乘法 k·G。 */
    public ECPoint basePointMul(BigInteger k) {
        return multiply(G, k);
    }

    /** 点加法 P + Q。 */
    public ECPoint add(ECPoint p, ECPoint q) {
        return p.add(q).normalize();
    }

    /** SEC1 非压缩编码（65 字节）。 */
    public byte[] encode(ECPoint p) {
        return p.getEncoded(false);
    }

    /**
     * SEC1 解码，并校验点在曲线上。
     *
     * @throws IllegalArgumentException 点非法或不在曲线上
     */
    public ECPoint decode(byte[] data) {
        if (data.length != POINT_LEN || data[0] != 0x04) {
            throw new IllegalArgumentException("invalid SEC1 uncompressed point");
        }
        ECPoint p = CURVE.decodePoint(data).normalize();
        if (p.isInfinity() || !p.isValid()) {
            throw new IllegalArgumentException("point not on curve");
        }
        return p;
    }

    /** 取仿射 X 坐标的 32 字节大端编码。 */
    public byte[] affineX(ECPoint p) {
        return toFixed(p.normalize().getAffineXCoord().toBigInteger(), SCALAR_LEN);
    }

    /**
     * BigInteger → 固定长度无符号大端字节数组（左补零 / 截低位）。
     */
    public byte[] toFixed(BigInteger v, int size) {
        byte[] raw = v.toByteArray();
        byte[] out = new byte[size];
        int start = raw.length > size ? raw.length - size : 0;
        int len = Math.min(raw.length, size);
        System.arraycopy(raw, start, out, size - len, len);
        return out;
    }

    /**
     * H1 哈希到曲线（try-and-increment）。
     *
     * <p>仅 KGC 侧使用（用于 {@code Q_i = H1(ID || P_i)}），充电桩不参与该运算，
     * 因此无需跨语言互操作；此处保持与原协议文档一致的确定性算法：</p>
     * <ol>
     *   <li>{@code digest = SHA256(parts... || counter_be32)}，counter 从 0 起；</li>
     *   <li>{@code x = digest mod P}；</li>
     *   <li>解 {@code y² = x³ + ax + b}，用 {@code y = rhs^((P+1)/4) mod P}；</li>
     *   <li>按 digest 末字节 LSB 选择 y 的奇偶。</li>
     * </ol>
     *
     * @throws IllegalStateException 256 次尝试仍未命中曲线
     */
    public ECPoint hashToCurve(byte[]... parts) {
        MessageDigest md = sha256Digest();
        BigInteger a = CURVE.getA().toBigInteger();
        BigInteger b = CURVE.getB().toBigInteger();
        BigInteger sqrtExp = P.add(BigInteger.ONE).divide(BigInteger.valueOf(4));
        for (int counter = 0; counter < 256; counter++) {
            MessageDigest mdc = cloneDigest(md);
            for (byte[] part : parts) {
                mdc.update(part);
            }
            mdc.update(new byte[]{
                (byte) (counter >>> 24), (byte) (counter >>> 16),
                (byte) (counter >>> 8), (byte) counter
            });
            byte[] digest = mdc.digest();
            BigInteger x = new BigInteger(1, digest).mod(P);
            if (x.signum() == 0) {
                continue;
            }
            BigInteger rhs = x.modPow(BigInteger.valueOf(3), P)
                .add(a.multiply(x)).add(b).mod(P);
            BigInteger y = rhs.modPow(sqrtExp, P);
            if (!y.multiply(y).mod(P).equals(rhs)) {
                continue;
            }
            boolean wantEven = (digest[digest.length - 1] & 1) == 0;
            boolean yEven = !y.testBit(0);
            if (wantEven != yEven) {
                y = P.subtract(y);
            }
            byte[] enc = new byte[POINT_LEN];
            enc[0] = 0x04;
            System.arraycopy(toFixed(x, SCALAR_LEN), 0, enc, 1, SCALAR_LEN);
            System.arraycopy(toFixed(y, SCALAR_LEN), 0, enc, 1 + SCALAR_LEN, SCALAR_LEN);
            return decode(enc);
        }
        throw new IllegalStateException("hashToCurve: failed after 256 attempts");
    }

    /** SHA-256 便捷方法。 */
    public static byte[] sha256(byte[] data) {
        return sha256Digest().digest(data);
    }

    private static MessageDigest sha256Digest() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    private static MessageDigest cloneDigest(MessageDigest md) {
        try {
            return (MessageDigest) md.clone();
        } catch (CloneNotSupportedException e) {
            return sha256Digest();
        }
    }
}
