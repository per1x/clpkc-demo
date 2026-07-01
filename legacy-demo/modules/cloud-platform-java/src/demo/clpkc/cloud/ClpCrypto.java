package demo.clpkc.cloud;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Cloud 平台密码学模块。
 *
 * <p>封装 CL-PKC（无证书公钥密码）方案的完整密码学操作流水线：
 * 密钥生成、密钥组合（部分私钥 + 用户密钥 → 完整密钥）、ECIES 解密、
 * Schnorr 签名/验签、会话密钥派生、HMAC 认证等。</p>
 *
 * <p>核心流水线（以 Cloud 端为例）：
 * <ol>
 *   <li>{@link #generateStaticKey} 生成用户静态密钥对 (x_i, P_i = x_i·G)</li>
 *   <li>从 KGC 获取加密的部分私钥 D_i，通过 {@link #eciesDecrypt} 解密</li>
 *   <li>{@link #hashPointToScalar} 将点哈希为标量 d_i = H2(D_i)</li>
 *   <li>完整私钥 sk_i = x_i + d_i (mod n)，派生公钥 Y_i = d_i·G</li>
 *   <li>{@link #sign} / {@link #verify} 基于 Schnorr 签名实现身份认证</li>
 *   <li>{@link #deriveSessionKey} 派生 ECDH 会话密钥</li>
 * </ol>
 *
 * <p>安全注意事项：</p>
 * <ul>
 *   <li>部分私钥通过 ECIES 加密传输，解密依赖用户静态密钥 x_i</li>
 *   <li>哈希到标量使用 SHA-256，返回值若为 0 则置为 1 防止退化</li>
 *   <li>Schnorr 签名包含 transcript 绑定防止重放/混淆攻击</li>
 *   <li>会话密钥派生包含双方身份、随机数和时间戳的 transcript 绑定</li>
 * </ul>
 */
public final class ClpCrypto {
    /**
     * Schnorr 签名记录。
     *
     * @param rHex R 点的十六进制编码（65 字节 SEC1 非压缩）
     * @param sHex s 标量的十六进制编码（32 字节大端）
     */
    public record Signature(String rHex, String sHex) {
        public String toHex() {
            return rHex + sHex;
        }
    }

    /**
     * 密钥材料记录。
     *
     * @param secretScalar  秘密标量（私钥），范围 [1, N-1]
     * @param publicKeyHex  对应公钥的十六进制 SEC1 非压缩编码
     */
    public record KeyMaterial(BigInteger secretScalar, String publicKeyHex) {
    }

    /**
     * 完整密钥记录。
     *
     * @param privateScalar    完整私钥 sk_i = x_i + d_i (mod n)
     * @param derivedPublicHex 派生公钥 Y_i = d_i·G 的十六进制 SEC1 编码
     */
    public record FullKey(BigInteger privateScalar, String derivedPublicHex) {
    }

    private final Secp256r1 curve = new Secp256r1();

    /**
     * 生成用户静态密钥对 (x_i, P_i = x_i·G)。
     *
     * <p>随机生成秘密标量 x_i ∈ [1, N-1]，计算对应的公钥点 P_i = x_i·G，
     * 以 SEC1 非压缩十六进制形式返回公钥。</p>
     *
     * @return 包含秘密标量和公钥十六进制编码的 {@link KeyMaterial}
     */
    public KeyMaterial generateStaticKey() {
        BigInteger x = curve.randomScalar();
        return new KeyMaterial(x, Hexs.encode(curve.encode(curve.multiply(Secp256r1.G, x))));
    }

    /**
     * 由静态秘密标量和部分私钥点计算完整私钥 sk_i。
     *
     * <p>步骤：解码部分私钥点 D_i → 哈希到标量 d_i = H2(D_i) →
     * sk_i = x_i + d_i (mod n)。</p>
     *
     * @param secret          用户的静态秘密标量 x_i
     * @param partialPointHex 十六进制编码的部分私钥点 D_i（SEC1 非压缩，65 字节）
     * @return 完整私钥 sk_i = x_i + d_i (mod N)
     */
    public BigInteger composeFullPrivate(BigInteger secret, String partialPointHex) {
        Secp256r1.Point D_i = curve.decode(Hexs.decode(partialPointHex));
        BigInteger d_i = hashPointToScalar(D_i);
        return secret.add(d_i).mod(Secp256r1.N);
    }

    /**
     * 由静态公钥和派生公钥计算完整公钥 PK_i = P_i + Y_i。
     *
     * <p>解码两个点后执行椭圆曲线点加法，返回 SEC1 非压缩十六进制编码。</p>
     *
     * @param publicKeyHex      用户静态公钥 P_i 的十六进制 SEC1 编码
     * @param derivedPublicHex  派生公钥 Y_i 的十六进制 SEC1 编码
     * @return 完整公钥 PK_i = P_i + Y_i 的十六进制 SEC1 编码
     */
    public String deriveFullPublic(String publicKeyHex, String derivedPublicHex) {
        Secp256r1.Point P_i = curve.decode(Hexs.decode(publicKeyHex));
        Secp256r1.Point Y_i = curve.decode(Hexs.decode(derivedPublicHex));
        return Hexs.encode(curve.encode(curve.add(P_i, Y_i)));
    }

    /**
     * 完整密钥组合流水线：解密部分私钥 → 计算完整私钥及派生公钥。
     *
     * <p>这是 {@link #eciesDecrypt} + {@link #hashPointToScalar} + 标量组合的
     * 一体化操作。步骤：
     * <ol>
     *   <li>ECIES 解密加密的部分私钥，得到明文部分私钥点 D_i</li>
     *   <li>将 D_i 哈希到标量 d_i = H2(D_i)</li>
     *   <li>完整私钥 sk_i = x_i + d_i (mod n)</li>
     *   <li>派生公钥 Y_i = d_i·G</li>
     * </ol>
     *
     * @param secret              用户静态秘密标量 x_i
     * @param encryptedPartialHex ECIES 加密的部分私钥十六进制串
     * @return 包含完整私钥 sk_i 和派生公钥 Y_i 的 {@link FullKey}
     */
    public FullKey composeFullKey(BigInteger secret, String encryptedPartialHex) {
        byte[] partialBytes = eciesDecrypt(encryptedPartialHex, secret);
        Secp256r1.Point D_i = curve.decode(partialBytes);
        BigInteger d_i = hashPointToScalar(D_i);
        BigInteger sk_i = secret.add(d_i).mod(Secp256r1.N);
        Secp256r1.Point Y_i = curve.multiply(Secp256r1.G, d_i);
        return new FullKey(sk_i, Hexs.encode(curve.encode(Y_i)));
    }

    /**
     * H2 哈希函数：将椭圆曲线点哈希为标量（mod N）。
     *
     * <p>实现：将 x 坐标和 y 坐标各序列化为 32 字节无符号大端，拼接为 64 字节，
     * 做 SHA-256 哈希后取模 N。若结果为 0，返回 1 以防止退化为零元。</p>
     *
     * <p>密码学意义：H2 是 CL-PKC 方案中将点映射到标量的关键哈希函数。</p>
     *
     * @param p 椭圆曲线仿射点
     * @return H2(p) ∈ [1, N-1]
     */
    public BigInteger hashPointToScalar(Secp256r1.Point p) {
        byte[] x = curve.toFixed(p.x(), 32);
        byte[] y = curve.toFixed(p.y(), 32);
        byte[] combined = new byte[64];
        System.arraycopy(x, 0, combined, 0, 32);
        System.arraycopy(y, 0, combined, 32, 32);
        BigInteger v = new BigInteger(1, sha256(combined)).mod(Secp256r1.N);
        return v.equals(BigInteger.ZERO) ? BigInteger.ONE : v;
    }

    /**
     * ECIES 解密：使用静态秘密标量解密 ECIES 密文。
     *
     * <p>密文格式：R（65 字节 SEC1）|| IV（12 字节）|| AES-GCM 密文+Tag。
     * 解密步骤：
     * <ol>
     *   <li>从密文中提取临时公钥 R</li>
     *   <li>计算共享秘密 S = x_i·R（ECDH）</li>
     *   <li>对 S.x 做 SHA-256 派生 AES-256 密钥</li>
     *   <li>使用 AES-256-GCM 解密（自动验证认证标签）</li>
     * </ol>
     *
     * <p>安全保证：AES-GCM 的认证标签提供密文完整性保护，篡改密文会导致
     * AEADBadTagException。</p>
     *
     * @param encryptedBlobHex ECIES 密文的十六进制编码
     * @param secretScalar     接收方的静态秘密标量 x_i
     * @return 解密后的明文字节数组
     * @throws IllegalStateException 解密/认证失败（密钥不匹配或密文被篡改）
     */
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

    /**
     * Schnorr 签名生成。
     *
     * <p>签名方程（针对 transcript T）：
     * <ol>
     *   <li>生成随机 ephemeral 标量 k ∈ [1, N-1]</li>
     *   <li>计算承诺 R = k·G，编码 R</li>
     *   <li>挑战 e = H(R || T)，其中 H 由 {@link #hashToScalar} 实现</li>
     *   <li>响应 s = k + e·sk_i (mod n)</li>
     *   <li>输出签名 (R_hex, s_hex)</li>
     * </ol>
     *
     * <p>安全性：transcript 绑定了 ra（对方随机数）、id（身份）、wb（对方公钥编码）、
     * t（时间戳），防止跨会话签名嵌入和重放攻击。</p>
     *
     * @param ra          对方提供的随机数（字节数组）
     * @param id          签名者身份标识
     * @param wb          对方公钥 SEC1 编码（字节数组）
     * @param t           时间戳字符串
     * @param fullPrivate 签名者完整私钥 sk_i
     * @return Schnorr 签名 (R_hex, s_hex)
     */
    public Signature sign(byte[] ra, String id, byte[] wb, String t, BigInteger fullPrivate) {
        byte[] transcript = transcript(ra, id, wb, t);
        BigInteger k = curve.randomScalar();
        Secp256r1.Point rPoint = curve.multiply(Secp256r1.G, k);
        byte[] rEncoded = curve.encode(rPoint);
        BigInteger e = hashToScalar(rEncoded, transcript);
        BigInteger s = k.add(e.multiply(fullPrivate)).mod(Secp256r1.N);
        return new Signature(Hexs.encode(rEncoded), Hexs.encode(curve.toFixed(s, 32)));
    }

    /**
     * Schnorr 签名验证。
     *
     * <p>验证方程：s·G ≟ R + e·PK_i，其中 e = H(R || transcript)。
     * 步骤：
     * <ol>
     *   <li>从签名中解析 R 和 s</li>
     *   <li>重建相同的 transcript 和挑战 e</li>
     *   <li>计算左式 L = s·G</li>
     *   <li>计算右式 R' = R + e·PK_i</li>
     *   <li>验证 L.x == R'.x 且 L.y == R'.y，且 L 不是无穷远点</li>
     * </ol>
     *
     * <p>安全要点：必须验证左式不是无穷远点（防止签名 s=0 情况下的小群攻击）。</p>
     *
     * @param ra            对方提供的随机数（字节数组）
     * @param id            签名者身份标识
     * @param wb            对方公钥 SEC1 编码（字节数组）
     * @param t             时间戳字符串
     * @param sigHex        签名的十六进制编码（R_hex || s_hex，共 65+32 字节）
     * @param fullPublicHex 签名者完整公钥 PK_i 的十六进制 SEC1 编码
     * @return true 当且仅当签名有效
     */
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

    /**
     * 派生 ECDH + transcript 绑定的会话密钥。
     *
     * <p>计算共享秘密 shared = ephemeralScalar · peerPoint（ECDH），
     * 取 shared.x 的 32 字节编码，与双方随机数 (ra, rb)、身份 (ida, idb)、
     * 时间戳 (ta, tb) 拼接后做 SHA-256 哈希，得到最终会话密钥。</p>
     *
     * <p>安全性：会话密钥同时绑定了 ECDH 密钥协商结果和完整的协议 transcript，
     * 防止未知密钥共享（UKS）攻击和中间人篡改身份。</p>
     *
     * @param ephemeralScalar 己方临时私钥标量
     * @param peerPoint       对方临时公钥 SEC1 编码（字节数组，65 字节）
     * @param ra              己方随机数（字节数组）
     * @param rb              对方随机数（字节数组）
     * @param ida             己方身份标识
     * @param idb             对方身份标识
     * @param ta              己方时间戳字符串
     * @param tb              对方时间戳字符串
     * @return 会话密钥的十六进制编码（SHA-256 输出）
     */
    public String deriveSessionKey(BigInteger ephemeralScalar, byte[] peerPoint, byte[] ra, byte[] rb, String ida, String idb, String ta, String tb) {
        Secp256r1.Point shared = curve.multiply(curve.decode(peerPoint), ephemeralScalar);
        byte[] sharedX = curve.toFixed(shared.x(), 32);
        return Hexs.encode(hash(sharedX, ra, rb, ida.getBytes(StandardCharsets.UTF_8), idb.getBytes(StandardCharsets.UTF_8),
            ta.getBytes(StandardCharsets.UTF_8), tb.getBytes(StandardCharsets.UTF_8)));
    }

    /**
     * HMAC-SHA256 消息认证码计算。
     *
     * <p>用于 Cloud 平台与充电桩之间的预共享密钥认证（challenge-response）。</p>
     *
     * @param key  HMAC 密钥（预共享密钥）
     * @param data 待认证的数据
     * @return 32 字节的 HMAC-SHA256
     * @throws IllegalStateException 若 HMAC 实现不可用
     */
    public byte[] hmac(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * 遗留哈希辅助函数 H1：对身份 id 和公钥编码做联合哈希得到标量。
     *
     * <p>将 id 的 UTF-8 字节和公钥 SEC1 解码后拼接做 SHA-256，取模 N 得到标量。
     * 若结果为 0 则返回 1。</p>
     *
     * @param id            身份标识字符串
     * @param publicKeyHex  公钥的十六进制 SEC1 编码
     * @return H1(id, P) ∈ [1, N-1]
     */
    public BigInteger h1(String id, String publicKeyHex) {
        return hashToScalar(id.getBytes(StandardCharsets.UTF_8), Hexs.decode(publicKeyHex));
    }

    /**
     * SHA-256 哈希（包级可见，供同包类使用）。
     *
     * @param data 待哈希的字节数组
     * @return 32 字节的 SHA-256 哈希值
     * @throws IllegalStateException 若 SHA-256 实现不可用
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
     * 将多个字节数组联合哈希后输出模 N 的标量（内部辅助方法）。
     *
     * <p>依次更新 SHA-256 摘要，最终取模 N。若结果为 0，返回 1。</p>
     *
     * @param parts 待哈希的多个字节数组，按顺序拼接
     * @return SHA-256(parts...) mod N，最小为 1
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

    /**
     * 构建碰撞抗性的 transcript 缓冲区。
     *
     * <p>格式：[2 字节长度前缀][数据] × 4，依次为 ra、id、wb、t。
     * 长度前缀采用大端序，防止不同字段间的边界混淆攻击。</p>
     *
     * @param ra 随机数字节数组
     * @param id 身份标识字符串
     * @param wb 公钥 SEC1 编码字节数组
     * @param t  时间戳字符串
     * @return 拼接后的 transcript 字节数组
     */
    private byte[] transcript(byte[] ra, String id, byte[] wb, String t) {
        byte[] idBytes = id.getBytes(StandardCharsets.UTF_8);
        byte[] tBytes = t.getBytes(StandardCharsets.UTF_8);
        int total = 2 + ra.length + 2 + idBytes.length + 2 + wb.length + 2 + tBytes.length;
        byte[] out = new byte[total];
        int pos = 0;
        out[pos++] = (byte)(ra.length >> 8);
        out[pos++] = (byte)(ra.length);
        System.arraycopy(ra, 0, out, pos, ra.length);
        pos += ra.length;
        out[pos++] = (byte)(idBytes.length >> 8);
        out[pos++] = (byte)(idBytes.length);
        System.arraycopy(idBytes, 0, out, pos, idBytes.length);
        pos += idBytes.length;
        out[pos++] = (byte)(wb.length >> 8);
        out[pos++] = (byte)(wb.length);
        System.arraycopy(wb, 0, out, pos, wb.length);
        pos += wb.length;
        out[pos++] = (byte)(tBytes.length >> 8);
        out[pos++] = (byte)(tBytes.length);
        System.arraycopy(tBytes, 0, out, pos, tBytes.length);
        return out;
    }

    /**
     * 将多个字节数组联合做 SHA-256 哈希（内部辅助方法，用于会话密钥派生）。
     *
     * <p>依次更新 SHA-256 摘要后返回完整哈希值（不做模运算）。</p>
     *
     * @param parts 待哈希的多个字节数组，按顺序拼接
     * @return 32 字节的 SHA-256 哈希值
     */
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
}