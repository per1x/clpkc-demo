package demo.clpkc.kgc;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * secp256r1（NIST P-256）椭圆曲线的完整实现。
 *
 * <p>该类提供了 secp256r1 曲线上的核心运算，包括：标量乘法（双倍-加法算法）、
 * 点加法、点倍乘、点的 SEC1 非压缩格式编解码、曲线上点验证，
 * 以及 try-and-increment 哈希到曲线（hash-to-curve）实现。</p>
 *
 * <h3>安全注意事项</h3>
 * <ul>
 *   <li>本实现为演示/教育用途，未针对侧信道攻击（如计时攻击、SPA/DPA）进行防护。</li>
 *   <li>随机数生成使用 {@link SecureRandom}，其安全性取决于底层操作系统的熵源。</li>
 *   <li>哈希到曲线采用 try-and-increment 方法，适用于 CL-PKC 协议中的 H1 函数。</li>
 * </ul>
 *
 * @see <a href="https://www.secg.org/sec1-v2.pdf">SEC 1: Elliptic Curve Cryptography</a>
 * @see <a href="https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf">FIPS 186-5</a>
 */
public final class Secp256r1 {

    /** 曲线素数域阶 P = 2²²⁴(2³² − 1) + 2¹⁹² + 2⁹⁶ − 1。 */
    public static final BigInteger P = new BigInteger("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16);

    /** 曲线参数 a（secp256r1 中 a = −3 mod P）。 */
    public static final BigInteger A = new BigInteger("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc", 16);

    /** 曲线参数 b。 */
    public static final BigInteger B = new BigInteger("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16);

    /** 基点 G 的阶（循环子群的阶）。 */
    public static final BigInteger N = new BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16);

    /** secp256r1 曲线的生成元（基点）G。 */
    public static final Point G = new Point(
        new BigInteger("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16),
        new BigInteger("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16),
        false
    );

    /**
     * 椭圆曲线上的点，使用仿射坐标表示。
     *
     * @param x        点的 x 坐标
     * @param y        点的 y 坐标
     * @param infinity 是否为无穷远点（单位元）
     */
    public record Point(BigInteger x, BigInteger y, boolean infinity) {
    }

    /** 用于生成密码学安全随机数的随机源。 */
    private final SecureRandom random = new SecureRandom();

    /**
     * 生成一个在 [1, N−1] 范围内的密码学安全随机标量。
     *
     * <p>使用拒绝采样法：不断生成随机大整数，直到其值在有效范围内。
     * 由于 N 接近 2²⁵⁶，平均只需 1 次尝试即可得到有效值。</p>
     *
     * <p>安全说明：该方法生成的标量可作为 ECDSA 签名中的随机数 k
     * 或 ECIES 中的临时私钥使用。</p>
     *
     * @return 满足 1 ≤ k &lt; N 的随机大整数
     */
    public BigInteger randomScalar() {
        BigInteger r;
        do {
            r = new BigInteger(N.bitLength(), random);
        } while (r.compareTo(BigInteger.ZERO) <= 0 || r.compareTo(N) >= 0);
        return r;
    }

    /**
     * 椭圆曲线标量乘法：计算 k·P（点 P 的 k 倍）。
     *
     * <p>使用经典的<strong>双倍-加法（double-and-add）</strong>算法，
     * 从标量 k 的最低有效位开始逐位处理。每次迭代对中间结果做倍乘，
     * 如果当前位为 1 则加上 P。</p>
     *
     * <p>该实现先将 k 模 N（曲线的阶）处理，确保结果在正确的子群中。
     * 时间复杂度 O(log k)，对于 256 位标量约需 256 次倍乘和平均 128 次加法。</p>
     *
     * <p>安全说明：该实现未使用 Montgomery Ladder 等恒定时间算法，
     * 可能受到计时攻击和功耗分析攻击。</p>
     *
     * @param p 曲线上的点（基点或任意点）
     * @param k 标量（乘数），将被自动模 N 处理
     * @return 标量乘法结果 k·P
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
     * 椭圆曲线点加法：计算 P + Q。
     *
     * <p>处理以下特殊情况：
     * <ul>
     *   <li>如果 P 是无穷远点，返回 Q。</li>
     *   <li>如果 Q 是无穷远点，返回 P。</li>
     *   <li>如果 P.x == Q.x：
     *     <ul>
     *       <li>若 P.y == −Q.y（即 P.y + Q.y ≡ 0 mod P），结果为无穷远点。</li>
     *       <li>否则 P == Q，调用倍乘函数 {@code doublePoint}。</li>
     *     </ul>
     *   </li>
     * </ul>
     * 一般情况下使用弦切法公式：λ = (y₂−y₁)/(x₂−x₁)。</p>
     *
     * @param p 第一个点
     * @param q 第二个点
     * @return 两点之和 P + Q
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
     * 椭圆曲线点倍乘（点加倍）：计算 2P。
     *
     * <p>使用以下公式计算切线斜率：
     * λ = (3x² + a) / (2y) mod P</p>
     *
     * <p>特殊情况：
     * <ul>
     *   <li>若 P 为无穷远点，返回无穷远点。</li>
     *   <li>若 y == 0，切线垂直，结果为无穷远点（2P = O）。</li>
     * </ul></p>
     *
     * @param p 要倍乘的点
     * @return 2P（点 p 的两倍）
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
     * 将曲线上的点编码为 SEC1 非压缩格式的 65 字节数组。
     *
     * <p>编码格式：{@code 0x04 || x (32 bytes) || y (32 bytes)}，
     * 其中 x 和 y 为固定 32 字节大端表示（无符号）。</p>
     *
     * <p>该格式与 OpenSSL、BouncyCastle 等主流库兼容。</p>
     *
     * @param p 要编码的曲线点
     * @return 65 字节的 SEC1 非压缩编码
     * @throws IllegalArgumentException 如果 p 为无穷远点（无法编码）
     */
    public byte[] encode(Point p) {
        if (p.infinity()) {
            throw new IllegalArgumentException("cannot encode infinity");
        }
        byte[] out = new byte[65];
        out[0] = 0x04;
        System.arraycopy(toFixed(p.x(), 32), 0, out, 1, 32);
        System.arraycopy(toFixed(p.y(), 32), 0, out, 33, 32);
        return out;
    }

    /**
     * 从 SEC1 非压缩格式的 65 字节数组解码曲线点。
     *
     * <p>解码后会自动验证该点是否在曲线上（调用 {@link #isOnCurve}）。
     * 通过验证可防止小子群攻击和无效曲线攻击。</p>
     *
     * @param data 65 字节的 SEC1 非压缩编码（必须以 0x04 开头）
     * @return 解码后的曲线点
     * @throws IllegalArgumentException 如果数据长度不是 65 字节、格式不正确或点不在曲线上
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
     * 验证坐标 (x, y) 是否在 secp256r1 曲线上。
     *
     * <p>曲线方程：y² ≡ x³ + ax + b (mod P)。</p>
     *
     * <p>在接收外部公钥或解码点时，<strong>必须进行此验证</strong>，
     * 以防止无效曲线攻击（攻击者发送不在曲线上的点以提取私钥信息）。</p>
     *
     * @param x 点的 x 坐标
     * @param y 点的 y 坐标
     * @return 如果点满足曲线方程则返回 {@code true}
     */
    public boolean isOnCurve(BigInteger x, BigInteger y) {
        BigInteger x3 = x.modPow(BigInteger.valueOf(3), P);
        BigInteger ax = A.multiply(x).mod(P);
        BigInteger rhs = x3.add(ax).add(B).mod(P);
        BigInteger y2 = y.multiply(y).mod(P);
        return y2.equals(rhs);
    }

    /**
     * 将 BigInteger 转换为固定长度的字节数组（大端、无符号）。
     *
     * <p>如果值需要的字节数少于 {@code size}，则在前面填充 0x00。
     * 如果值需要的字节数多于 {@code size}，则截取低位字节。
     * 此方法用于编码坐标到 32 字节固定长度。</p>
     *
     * @param v    要转换的大整数
     * @param size 目标字节数组长度
     * @return 固定长度的字节数组
     */
    public byte[] toFixed(BigInteger v, int size) {
        byte[] raw = v.toByteArray();
        byte[] out = new byte[size];
        int copyStart = raw.length > size ? raw.length - size : 0;
        int copyLen = Math.min(raw.length, size);
        System.arraycopy(raw, copyStart, out, size - copyLen, copyLen);
        return out;
    }

    /**
     * 哈希到曲线（hash-to-curve），使用 try-and-increment 方法。
     *
     * <p>该方法是 CL-PKC 协议中 H1 哈希函数的实现，将任意数据
     * 映射到 secp256r1 曲线上的点。算法流程如下：</p>
     *
     * <ol>
     *   <li>使用 SHA-256 对输入数据 + 4 字节计数器（大端）进行哈希。</li>
     *   <li>将哈希值视为大整数，模 P 作为候选 x 坐标。</li>
     *   <li>计算右手边 rhs = x³ + ax + b (mod P)。</li>
     *   <li>利用 P ≡ 3 (mod 4) 的性质，使用 Tonelli-Shanks 捷径
     *       计算平方根：y = rhs^((P+1)/4) mod P。</li>
     *   <li>验证 y² ≡ rhs (mod P)。若不成立，递增计数器重试。</li>
     *   <li>根据哈希摘要最后一比特的奇偶性选择 y 或 P−y。</li>
     * </ol>
     *
     * <p>最多尝试 256 次，超过则抛出异常。对于 SHA-256 哈希，
     * 每次尝试命中曲线的概率约为 1/2，因此平均 2 次尝试即可成功。</p>
     *
     * <p>安全说明：try-and-increment 方法不是恒定时间的，
     * 存在潜在的计时侧信道。生产环境建议使用 BLS 哈希到曲线标准
     * （RFC 9380）中的方法。</p>
     *
     * @param dataParts 要哈希的数据片段（将被依次送入哈希函数）
     * @return 曲线上的点，该点与输入数据满足哈希到曲线的映射关系
     * @throws IllegalStateException 如果 256 次尝试后仍未找到有效点
     */
    public Point hashToCurve(byte[]... dataParts) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            for (int counter = 0; counter < 256; counter++) {
                MessageDigest mdc = (MessageDigest) md.clone();
                for (byte[] part : dataParts) {
                    mdc.update(part);
                }
                mdc.update(new byte[]{
                    (byte) (counter >> 24), (byte) (counter >> 16),
                    (byte) (counter >> 8), (byte) counter
                });
                byte[] digest = mdc.digest();

                BigInteger x = new BigInteger(1, digest).mod(P);
                if (x.signum() == 0) continue;

                // 计算 y² = x³ + ax + b (mod P)
                BigInteger x3 = x.modPow(BigInteger.valueOf(3), P);
                BigInteger ax = A.multiply(x).mod(P);
                BigInteger rhs = x3.add(ax).add(B).mod(P);

                // 利用 P ≡ 3 (mod 4) 的性质：sqrt(a) = a^((P+1)/4) mod P
                BigInteger exp = P.add(BigInteger.ONE).divide(BigInteger.valueOf(4));
                BigInteger y = rhs.modPow(exp, P);

                BigInteger y2 = y.multiply(y).mod(P);
                if (!y2.equals(rhs)) continue;

                // 根据摘要最后一比特的奇偶性选择 y 或 P−y
                boolean wantEven = (digest[digest.length - 1] & 1) == 0;
                boolean yEven = y.mod(BigInteger.TWO).signum() == 0;
                if (wantEven != yEven) {
                    y = P.subtract(y);
                }
                return new Point(x, y, false);
            }
            throw new IllegalStateException("hashToCurve: failed after 256 attempts");
        } catch (Exception e) {
            throw new IllegalStateException("hashToCurve: " + e.getMessage(), e);
        }
    }
}
