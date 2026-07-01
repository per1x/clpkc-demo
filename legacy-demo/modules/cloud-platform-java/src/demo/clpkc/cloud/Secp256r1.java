package demo.clpkc.cloud;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * secp256r1 椭圆曲线实现。
 *
 * <p>实现 NIST P-256 (secp256r1) 椭圆曲线的核心操作，包括点乘（标量乘法）、
 * 点加、倍点、SEC1 非压缩编码/解码、曲线点验证等。本实现采用简单的
 * double-and-add 算法，适用于 CL-PKC（无证书公钥密码）方案的演示用途。</p>
 *
 * <p>安全注意事项：</p>
 * <ul>
 *   <li>本实现未做旁路攻击防护（如恒定时间运算），仅用于演示。</li>
 *   <li>randomScalar 使用 rejection sampling 保证标量均匀分布在 [1, N-1]。</li>
 *   <li>decode 会调用 isOnCurve 验证点是否在曲线上，防止无效曲线攻击。</li>
 * </ul>
 *
 * @see <a href="https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf">NIST FIPS 186-5</a>
 */
public final class Secp256r1 {
    /** 素数 P = 2²⁵⁶ − 2²²⁴ + 2¹⁹² + 2⁹⁶ − 1，secp256r1 的有限域 F_p */
    public static final BigInteger P = new BigInteger("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16);
    /** 曲线参数 a = P − 3，secp256r1 的 a 系数（短 Weierstrass 形式 y² = x³ + ax + b） */
    public static final BigInteger A = new BigInteger("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc", 16);
    /** 曲线参数 b（SEC 2 标准 secp256r1 的 b 系数），在 {@link #isOnCurve} 校验中使用 */
    public static final BigInteger B = new BigInteger("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16);
    /** 基点 G 的阶 n（即 #E(F_p) = n），用于标量运算的模数及标量范围限制 */
    public static final BigInteger N = new BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16);
    /** 基点 G，SEC 2 标准 secp256r1 的生成元（非无穷远点） */
    public static final Point G = new Point(
        new BigInteger("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16),
        new BigInteger("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16),
        false
    );

    /**
     * 椭圆曲线仿射点记录。
     *
     * @param x        仿射 x 坐标（为无穷远点时无意义）
     * @param y        仿射 y 坐标（为无穷远点时无意义）
     * @param infinity 是否为无穷远点 O
     */
    public record Point(BigInteger x, BigInteger y, boolean infinity) {
    }

    private final SecureRandom random = new SecureRandom();

    /**
     * 生成 [1, N-1] 范围内的随机标量。
     *
     * <p>采用 rejection sampling：生成与 N 同比特长度的随机大整数，若落在
     * [0, N) 范围外或等于 0 则重新生成，确保输出均匀分布在合法区间。</p>
     *
     * <p>安全性：使用 {@link SecureRandom} 源，适合密钥生成等密码学场景。</p>
     *
     * @return [1, N-1] 范围内的随机 {@link BigInteger} 标量
     */
    public BigInteger randomScalar() {
        BigInteger r;
        do {
            r = new BigInteger(N.bitLength(), random);
        } while (r.compareTo(BigInteger.ZERO) <= 0 || r.compareTo(N) >= 0);
        return r;
    }

    /**
     * 标量乘法 k·P（double-and-add 算法）。
     *
     * <p>将标量 k 对阶 N 取模后，从低位到高位逐比特执行 point doubling 和
     * conditional addition。结果始终为曲线上的仿射点（包括无穷远点）。</p>
     *
     * <p>注意：如果 k ≡ 0 (mod N)，将返回无穷远点 O。</p>
     *
     * @param p 基点（曲线上的仿射点）
     * @param k 标量乘数
     * @return 乘法结果 k·P，可能为无穷远点
     */
    public Point multiply(Point p, BigInteger k) {
        Point result = new Point(BigInteger.ZERO, BigInteger.ZERO, true);
        Point addend = p;
        BigInteger n = k.mod(N);
        while (n.signum() > 0) {
            if (n.testBit(0)) {
                result = add(result, addend);
            }
            addend = doublePoint(addend);
            n = n.shiftRight(1);
        }
        return result;
    }

    /**
     * 点加法 P + Q（仿射坐标）。
     *
     * <p>处理四种情况：
     * <ul>
     *   <li>P 或 Q 为无穷远点 → 返回另一个点</li>
     *   <li>P.x = Q.x 且 P.y = −Q.y → 返回无穷远点（相加抵消）</li>
     *   <li>P.x = Q.x 且 P.y = Q.y → 退化为倍点运算 {@link #doublePoint}</li>
     *   <li>一般情况 → 按椭圆曲线加法定律 λ = (y₂−y₁)/(x₂−x₁) 计算</li>
     * </ul>
     *
     * @param p 加数点 P
     * @param q 加数点 Q
     * @return P + Q 的结果点
     */
    public Point add(Point p, Point q) {
        if (p.infinity()) {
            return q;
        }
        if (q.infinity()) {
            return p;
        }
        if (p.x().equals(q.x())) {
            if (p.y().add(q.y()).mod(P).equals(BigInteger.ZERO)) {
                return new Point(BigInteger.ZERO, BigInteger.ZERO, true);
            }
            return doublePoint(p);
        }
        BigInteger lambda = q.y().subtract(p.y()).multiply(q.x().subtract(p.x()).mod(P).modInverse(P)).mod(P);
        BigInteger rx = lambda.multiply(lambda).subtract(p.x()).subtract(q.x()).mod(P);
        BigInteger ry = lambda.multiply(p.x().subtract(rx)).subtract(p.y()).mod(P);
        return new Point(rx, ry, false);
    }

    /**
     * 倍点运算 2·P（内部辅助方法）。
     *
     * <p>当 P 为无穷远点或 y=0（2·P 退化为无穷远点）时返回 O。
     * 一般情况按椭圆曲线倍点公式 λ = (3x₁² + a) / (2y₁) 计算。</p>
     *
     * @param p 待倍乘的点 P
     * @return 倍乘结果 2·P
     */
    private Point doublePoint(Point p) {
        if (p.infinity() || p.y().equals(BigInteger.ZERO)) {
            return new Point(BigInteger.ZERO, BigInteger.ZERO, true);
        }
        BigInteger lambda = p.x().multiply(p.x()).multiply(BigInteger.valueOf(3)).add(A)
            .multiply(p.y().multiply(BigInteger.TWO).modInverse(P)).mod(P);
        BigInteger rx = lambda.multiply(lambda).subtract(p.x().shiftLeft(1)).mod(P);
        BigInteger ry = lambda.multiply(p.x().subtract(rx)).subtract(p.y()).mod(P);
        return new Point(rx, ry, false);
    }

    /**
     * 按 SEC1 非压缩格式编码椭圆曲线点。
     *
     * <p>格式：0x04 || x（32 字节大端无符号）|| y（32 字节大端无符号），
     * 共 65 字节。无穷远点不会被序列化（此方法假设调用方仅传入仿射点）。</p>
     *
     * @param p 待编码的仿射点
     * @return 65 字节的 SEC1 非压缩编码
     */
    public byte[] encode(Point p) {
        byte[] out = new byte[65];
        out[0] = 0x04;
        System.arraycopy(toFixed(p.x(), 32), 0, out, 1, 32);
        System.arraycopy(toFixed(p.y(), 32), 0, out, 33, 32);
        return out;
    }

    /**
     * 从 SEC1 非压缩格式解码椭圆曲线点（含曲线点验证）。
     *
     * <p>校验规则：
     * <ul>
     *   <li>数据长度必须为 65 字节，且首字节必须为 0x04</li>
     *   <li>解码出的 (x, y) 必须满足 {@link #isOnCurve}（防止无效曲线攻击）</li>
     * </ul>
     *
     * <p>不满足以上任何条件时抛出 {@link IllegalArgumentException}。</p>
     *
     * @param data 65 字节的 SEC1 非压缩编码
     * @return 解码后的仿射点
     * @throws IllegalArgumentException 数据格式非法或点不在曲线上
     */
    public Point decode(byte[] data) {
        if (data.length != 65 || data[0] != 0x04) {
            throw new IllegalArgumentException("invalid point");
        }
        byte[] xb = Arrays.copyOfRange(data, 1, 33);
        byte[] yb = Arrays.copyOfRange(data, 33, 65);
        BigInteger x = new BigInteger(1, xb);
        BigInteger y = new BigInteger(1, yb);
        if (!isOnCurve(x, y)) {
            throw new IllegalArgumentException("point not on curve");
        }
        return new Point(x, y, false);
    }

    /**
     * 验证坐标 (x, y) 是否满足 secp256r1 曲线方程 y² ≡ x³ + ax + b (mod P)。
     *
     * <p>用于防止无效曲线攻击：接收外部提供的点时，必须调用此方法确认
     * 点在曲线上。这是 ECIES 解密和 Schnorr 验签中的关键防线。</p>
     *
     * @param x 待校验的 x 坐标
     * @param y 待校验的 y 坐标
     * @return true 当且仅当 (x, y) 在 secp256r1 曲线上
     */
    public boolean isOnCurve(BigInteger x, BigInteger y) {
        BigInteger x3 = x.modPow(BigInteger.valueOf(3), P);
        BigInteger ax = A.multiply(x).mod(P);
        BigInteger rhs = x3.add(ax).add(B).mod(P);
        BigInteger y2 = y.multiply(y).mod(P);
        return y2.equals(rhs);
    }

    /**
     * 将 {@link BigInteger} 转换为固定长度的字节数组（大端序，无符号）。
     *
     * <p>若原始字节数小于目标长度，前面补零（左填充）；若大于目标长度
     * （如原始值最高位带 0x00 标记位时），截取低 size 字节，以确保输出
     * 与目标长度一致。</p>
     *
     * @param v    待转换的大整数
     * @param size 目标字节长度（如坐标固定为 32）
     * @return 固定长度的无符号大端字节数组
     */
    public byte[] toFixed(BigInteger v, int size) {
        byte[] raw = v.toByteArray();
        byte[] out = new byte[size];
        int start = raw.length > size ? raw.length - size : 0;
        int len = Math.min(raw.length, size);
        System.arraycopy(raw, start, out, size - len, len);
        return out;
    }
}
