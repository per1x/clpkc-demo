package com.clpkc.cloud.crypto;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

/**
 * 国密 SM2 曲线（sm2p256v1）运算封装。点线上编码 x(32)‖y(32)（128 hex，无 04 前缀）。
 */
public final class EcCurve {

    private static final X9ECParameters PARAMS = GMNamedCurves.getByName("sm2p256v1");

    public static final ECCurve CURVE = PARAMS.getCurve();
    public static final ECPoint G = PARAMS.getG();
    public static final BigInteger N = PARAMS.getN();
    public static final BigInteger P = CURVE.getField().getCharacteristic();
    public static final ECDomainParameters DOMAIN = new ECDomainParameters(CURVE, G, N, PARAMS.getH());
    public static final int SCALAR_LEN = 32;

    public static final byte[] A_BYTES;
    public static final byte[] B_BYTES;
    public static final byte[] GX_BYTES;
    public static final byte[] GY_BYTES;

    private final SecureRandom random;

    static {
        ECPoint g = G.normalize();
        A_BYTES = toFixedStatic(CURVE.getA().toBigInteger());
        B_BYTES = toFixedStatic(CURVE.getB().toBigInteger());
        GX_BYTES = toFixedStatic(g.getAffineXCoord().toBigInteger());
        GY_BYTES = toFixedStatic(g.getAffineYCoord().toBigInteger());
    }

    public EcCurve() {
        this(new SecureRandom());
    }

    public EcCurve(SecureRandom random) {
        this.random = random;
    }

    public BigInteger randomScalar() {
        BigInteger k;
        do {
            k = new BigInteger(N.bitLength(), random);
        } while (k.signum() <= 0 || k.compareTo(N) >= 0);
        return k;
    }

    public ECPoint multiply(ECPoint p, BigInteger k) {
        return p.multiply(k.mod(N)).normalize();
    }

    public ECPoint basePointMul(BigInteger k) {
        return multiply(G, k);
    }

    public ECPoint add(ECPoint p, ECPoint q) {
        return p.add(q).normalize();
    }

    public byte[] encodeXY(ECPoint p) {
        ECPoint np = p.normalize();
        byte[] out = new byte[64];
        System.arraycopy(toFixed(np.getAffineXCoord().toBigInteger(), SCALAR_LEN), 0, out, 0, 32);
        System.arraycopy(toFixed(np.getAffineYCoord().toBigInteger(), SCALAR_LEN), 0, out, 32, 32);
        return out;
    }

    public String xyHex(ECPoint p) {
        return Hex.encode(encodeXY(p));
    }

    public ECPoint decodeXY(byte[] data) {
        if (data.length != 64) {
            throw new IllegalArgumentException("point must be 64 bytes (x||y)");
        }
        BigInteger x = new BigInteger(1, Arrays.copyOfRange(data, 0, 32));
        BigInteger y = new BigInteger(1, Arrays.copyOfRange(data, 32, 64));
        ECPoint p = CURVE.createPoint(x, y).normalize();
        if (p.isInfinity() || !p.isValid()) {
            throw new IllegalArgumentException("point not on curve");
        }
        return p;
    }

    public ECPoint pointFromHex(String hex) {
        return decodeXY(Hex.decode(hex));
    }

    public byte[] toFixed(BigInteger v, int size) {
        byte[] raw = v.toByteArray();
        byte[] out = new byte[size];
        int start = raw.length > size ? raw.length - size : 0;
        int len = Math.min(raw.length, size);
        System.arraycopy(raw, start, out, size - len, len);
        return out;
    }

    private static byte[] toFixedStatic(BigInteger v) {
        byte[] raw = v.toByteArray();
        byte[] out = new byte[SCALAR_LEN];
        int start = raw.length > SCALAR_LEN ? raw.length - SCALAR_LEN : 0;
        int len = Math.min(raw.length, SCALAR_LEN);
        System.arraycopy(raw, start, out, SCALAR_LEN - len, len);
        return out;
    }

    public static byte[] sm3(byte[] data) {
        SM3Digest md = new SM3Digest();
        md.update(data, 0, data.length);
        byte[] out = new byte[md.getDigestSize()];
        md.doFinal(out, 0);
        return out;
    }
}
