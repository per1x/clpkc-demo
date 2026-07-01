package demo.clpkc.kgc;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * CL-PKC（无证书公钥密码学）密钥生成中心（KGC）的密码学核心模块。
 *
 * <p>该类负责以下关键密码学操作：</p>
 * <ul>
 *   <li>生成 KGC 的主密钥对（主私钥 s 和主公钥 Ppub = s·G）。</li>
 *   <li>为客户端颁发部分私钥：D_i = s · H1(ID || P_i)。</li>
 *   <li>通过 ECIES（椭圆曲线集成加密方案）加密传输部分私钥，
 *       使用 AES-256-GCM 认证加密。</li>
 * </ul>
 *
 * <h3>ECIES 加密格式</h3>
 * <p>密文结构：{@code [R (65 字节)] || [IV (12 字节)] || [密文 + GCM 标签]}</p>
 * <ul>
 *   <li>R：临时公钥（SEC1 非压缩格式，65 字节）。</li>
 *   <li>IV：AES-GCM 初始化向量（12 字节随机数）。</li>
 *   <li>密文：AES-256-GCM 加密后的数据（包含 16 字节认证标签）。</li>
 * </ul>
 *
 * <h3>安全注意事项</h3>
 * <ul>
 *   <li>主私钥 s 仅存在于 KGC 内存中，<strong>绝不能泄露</strong>。</li>
 *   <li>AES-GCM 提供了认证加密（AEAD），确保数据的机密性和完整性。</li>
 *   <li>临时 ECDH 私钥 r 每次加密都重新生成，提供前向安全性。</li>
 *   <li>SHA-256 派生 AES 密钥时仅使用共享密钥的 x 坐标，
 *       未使用完整 KDF（如 HKDF），生产环境建议升级。</li>
 * </ul>
 *
 * @see Secp256r1
 */
public final class ClpCrypto {

    /** secp256r1 椭圆曲线实例。 */
    private final Secp256r1 curve = new Secp256r1();

    /** KGC 主私钥 s（密码学安全随机数，范围 [1, N−1]）。 */
    private final BigInteger masterSecret;

    /** KGC 主公钥 Ppub = s·G。 */
    private final Secp256r1.Point masterPublic;

    /**
     * 构造 ClpCrypto 实例，同时生成 KGC 主密钥对。
     *
     * <p>主私钥 s 使用 {@link Secp256r1#randomScalar()} 生成（密码学安全随机数），
     * 主公钥 Ppub 通过计算 s·G 得到。主密钥对在 KGC 生命周期内保持不变。</p>
     *
     * <p>安全说明：主私钥 s 仅存储在内存中，KGC 服务器
     * <strong>不得</strong>将其写入日志或通过网络传输。</p>
     */
    public ClpCrypto() {
        this.masterSecret = curve.randomScalar();
        this.masterPublic = curve.multiply(Secp256r1.G, masterSecret);
    }

    /**
     * 获取 KGC 主公钥的十六进制字符串表示。
     *
     * <p>返回的是主公钥 Ppub 的 SEC1 非压缩编码的 HEX 字符串（130 个十六进制字符，
     * 代表 65 字节）。客户端使用此公钥进行后续的密码学操作。</p>
     *
     * @return 主公钥的十六进制字符串（0x04 前缀 + 64 字符 x + 64 字符 y）
     */
    public String getMasterPublicHex() {
        return Hexs.encode(curve.encode(masterPublic));
    }

    /**
     * 颁发部分私钥：为指定客户端生成 CL-PKC 部分私钥。
     *
     * <p>CL-PKC 协议中，KGC 为每个客户端计算：
     * D_i = s · H1(ID || P_i)</p>
     *
     * <p>其中：
     * <ul>
     *   <li>s：KGC 主私钥。</li>
     *   <li>ID：客户端标识字符串（如用户名、设备 ID 等）。</li>
     *   <li>P_i：客户端静态公钥（SEC1 非压缩格式十六进制）。</li>
     *   <li>H1：哈希到曲线函数（try-and-increment 方法）。</li>
     *   <li>D_i：部分私钥（曲线上的点）。</li>
     * </ul></p>
     *
     * <p>安全说明：部分私钥 D_i 必须通过安全信道（本实现中使用 ECIES 加密）
     * 传输给客户端。任何人获取 D_i 都无法推导出主私钥 s（基于 ECDLP 困难问题）。</p>
     *
     * @param id            客户端标识字符串
     * @param publicKeyHex  客户端静态公钥的十六进制字符串（SEC1 非压缩编码）
     * @return 部分私钥 D_i（secp256r1 曲线上的点）
     */
    public Secp256r1.Point issuePartialPrivate(String id, String publicKeyHex) {
        Secp256r1.Point Q_i = curve.hashToCurve(
            id.getBytes(StandardCharsets.UTF_8), Hexs.decode(publicKeyHex));
        return curve.multiply(Q_i, masterSecret);
    }

    /**
     * 返回底层 secp256r1 曲线实例。
     *
     * <p>包级访问权限，仅供同一包内的 {@link KgcServer} 等类使用。</p>
     *
     * @return 曲线实例
     */
    Secp256r1 curve() {
        return curve;
    }

    /**
     * 旧版 H1 哈希辅助函数：将客户端 ID 和公钥哈希为标量。
     *
     * <p>该方法使用 {@link #hashToScalar} 将 ID 和公钥拼接后哈希，
     * 并将结果模 N 转换为标量。保留此方法是为了向后兼容。</p>
     *
     * <p>注意：CL-PKC 标准中的 H1 应为哈希到<strong>曲线</strong>（而非标量），
     * 新代码请使用 {@link #issuePartialPrivate} 中的 H1 到曲线实现。</p>
     *
     * @param id            客户端标识字符串
     * @param publicKeyHex  客户端公钥的十六进制字符串
     * @return 哈希结果模 N 后的标量值（范围 [1, N−1]）
     */
    public BigInteger h1(String id, String publicKeyHex) {
        return hashToScalar(id.getBytes(StandardCharsets.UTF_8), Hexs.decode(publicKeyHex));
    }

    /**
     * ECIES 加密：使用临时 ECDH + AES-256-GCM 加密明文。
     *
     * <p>加密过程：</p>
     * <ol>
     *   <li>生成临时私钥 r（密码学安全随机数）。</li>
     *   <li>计算临时公钥 R = r·G。</li>
     *   <li>计算共享密钥 S = r·P_recipient（ECDH）。</li>
     *   <li>取 S 的 x 坐标，SHA-256 派生为 AES-256 密钥。</li>
     *   <li>生成 12 字节随机 IV。</li>
     *   <li>使用 AES-256-GCM（128 位认证标签）加密明文。</li>
     *   <li>组装密文：R(65B) + IV(12B) + 密文+标签。</li>
     * </ol>
     *
     * <p>安全特性：
     * <ul>
     *   <li>临时密钥 r 每次加密都重新生成，提供<strong>前向安全性</strong>。</li>
     *   <li>AES-GCM 提供<strong>认证加密（AEAD）</strong>，同时保护机密性和完整性。</li>
     *   <li>IV 为随机数，不需要保密但绝不能重用同一个密钥-IV 对。</li>
     * </ul></p>
     *
     * @param plaintext               要加密的明文数据（不应包含敏感信息泄露）
     * @param recipientPublicKeyHex   接收方公钥的十六进制字符串（SEC1 非压缩编码）
     * @return 密文的十六进制字符串（ECIES 格式）
     * @throws IllegalStateException 如果加密过程中发生任何密码学异常
     */
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

    /**
     * SHA-256 哈希计算。
     *
     * <p>用于 ECIES 加密中从 ECDH 共享密钥派生 AES 密钥。
     * 注意：生产环境建议使用 HKDF（RFC 5869）替代裸 SHA-256，
     * 以提供更安全的密钥派生。</p>
     *
     * @param data 要哈希的数据
     * @return 32 字节的 SHA-256 哈希值
     */
    byte[] sha256(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return md.digest(data);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * 哈希到标量：将多个数据片段拼接后 SHA-256 哈希，结果模 N 得到标量。
     *
     * <p>用于旧版 H1 哈希函数（{@link #h1}）。零值被替换为 1，
     * 以避免标量为零的退化情况。</p>
     *
     * @param parts 要哈希的数据片段（按顺序拼接后送入哈希函数）
     * @return 哈希结果模 N 后的标量值（范围 [1, N−1]）
     */
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
