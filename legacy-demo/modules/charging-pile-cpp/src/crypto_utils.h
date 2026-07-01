#pragma once

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <map>
#include <memory>
#include <string>
#include <vector>

// ============================================================================
// @file crypto_utils.h
// @brief CL-PKC（无证书公钥密码体系）充电桩演示的密码学工具类声明
//
// 本文件定义了充电桩与云端之间进行安全通信所需的全部密码学原语，
// 包括：静态/临时密钥生成、部分私钥组装、派生公钥计算、
// Schnorr 签名/验签、ECDH 会话密钥派生、ECIES 解密、HMAC 等。
// 底层椭圆曲线使用 NIST P-256（secp256r1）。
// ============================================================================

// ---------------------------------------------------------------------------
/// @struct KeyMaterial
/// @brief 密钥材料结构体，用于保存一对椭圆曲线密钥（标量 + 点）
///
/// 标量以64字符零填充十六进制字符串存储（对应256位大整数），
/// 公钥点以 SEC1 非压缩格式（04 || X || Y，共130字符十六进制）存储。
// ---------------------------------------------------------------------------
struct KeyMaterial {
    std::string secret_hex;  ///< 私钥标量，64字符十六进制字符串（256位）
    std::string public_hex;  ///< 公钥点，SEC1 非压缩格式十六进制字符串（130字符）
};

// ---------------------------------------------------------------------------
/// @struct Signature
/// @brief Schnorr 签名结构体，保存签名(r, s)两个分量
///
/// r 分量为临时公钥点 R 的 SEC1 非压缩编码（130字符十六进制），
/// s 分量为标量值（64字符十六进制）。
/// to_hex() 方法将两个分量串联为完整签名十六进制字符串。
// ---------------------------------------------------------------------------
struct Signature {
    std::string r_hex;  ///< 临时公钥点 R 的十六进制编码（130字符）
    std::string s_hex;  ///< 标量 s 的十六进制编码（64字符）

    /// @brief 将签名序列化为 r_hex || s_hex 的拼接十六进制字符串
    /// @return 签名完整十六进制表示（194字符）
    std::string to_hex() const {
        return r_hex + s_hex;
    }
};

// ---------------------------------------------------------------------------
/// @class CryptoUtils
/// @brief 密码学工具类，封装 CL-PKC 协议所需的所有密码学运算
///
/// 构造时自动初始化 OpenSSL EC_GROUP（secp256r1）、大数上下文 BN_CTX
/// 以及曲线阶 order_，析构时自动释放资源。
///
/// 安全注意事项：
/// - 本类使用 OpenSSL 作为底层密码学后端，虽然它是 C++ 类，但成员变量
///   (group_/ctx_/order_) 是裸指针，不支持拷贝。可以移动，但当前未实现。
/// - random_scalar() 使用 BN_rand_range 生成随机标量，需要系统提供
///   足够的熵（正确播种随机数生成器）。
/// - 所有十六进制字符串均使用小写字母表示。
/// - 在 CL-PKC 协议中，部分私钥通过 ECIES 加密传输，只有持有静态私钥的
///   充电桩才能解密，从而防止中间人窃取。
// ---------------------------------------------------------------------------
class CryptoUtils {
public:
    /// @brief 构造函数：初始化 secp256r1 椭圆曲线群与相关上下文
    /// @throws 如果 OpenSSL 初始化失败（如内存不足），底层 API 返回 nullptr，
    ///         当前实现不做检查。生产环境中应添加错误处理。
    CryptoUtils();

    /// @brief 析构函数：释放 OpenSSL 资源（group_ / ctx_ / order_）
    ~CryptoUtils();

    // ========================================================================
    //                          密钥生成与组装
    // ========================================================================

    /// @brief 生成静态密钥对 (x, P = x·G)
    ///
    /// 生成流程：
    /// 1. 调用 random_scalar() 在 [1, n-1] 范围内生成随机标量 x
    /// 2. 计算公钥点 P = x · G（G 为 secp256r1 生成元）
    /// 3. 将 x 编码为64字符十六进制，P 编码为130字符十六进制
    ///
    /// @return KeyMaterial 包含 (secret_hex = x, public_hex = P)
    ///
    /// @note 此函数生成的密钥对既可作为用户的长期静态密钥，
    ///       也可作为临时 ECDH 密钥对。两者共用相同的生成逻辑。
    /// @warning 随机标量若为 0，random_scalar() 内部会重试直到非零。
    KeyMaterial generate_static_key();

    // ========================================================================
    //                          CL-PKC 部分私钥与完整密钥
    // ========================================================================

    /// @brief 组装完整私钥：sk_i = x_i + d_i (mod n)
    ///
    /// 流程：
    /// 1. 将 partial_hex 反序列化为椭圆曲线点 Q_partial
    /// 2. 调用 H2 哈希函数 hash_point_to_scalar() 将 Q_partial 映射为标量 d_i
    /// 3. 计算 sk_i = (x_i + d_i) mod n，x_i 为用户的静态私钥
    ///
    /// @param secret_hex 用户静态私钥 x_i 的十六进制字符串（64字符）
    /// @param partial_hex 从 KGC 收到的部分私钥点 Q_partial 的十六进制（130字符）
    ///                    注意：此处应为已通过 ECIES 解密后的明文形式
    /// @return 完整私钥 sk_i 的64字符十六进制字符串
    ///
    /// @note 根据 CL-PKC 协议，部分私钥 d_i = H2(ID_i || P_i) · s，
    ///       其中 s 为 KGC 主私钥。由于 KGC 代为计算，充电桩无需知道 s。
    ///       充电桩收到部分私钥后，将其与自身静态私钥相加得到完整私钥。
    /// @warning secret_hex 和 d_i 相加结果可能超过阶 n，因此需要 mod n 规约。
    std::string compose_full_private(const std::string& secret_hex, const std::string& partial_hex);

    /// @brief 计算派生公钥 Y_i = d_i · G
    ///
    /// 将输入的点序列化为坐标字节，通过 H2 哈希映射为标量 d_i，
    /// 然后计算 Y_i = d_i · G。
    ///
    /// @param point_hex 输入点（通常为部分私钥 Q_partial）的十六进制字符串（130字符）
    /// @return 派生公钥点 Y_i 的130字符十六进制字符串
    ///
    /// @note 此函数用于从部分私钥 Q_partial 推导对应的公钥 Y_i。
    ///       在 CL-PKC 中，完整公钥 = P_i + Y_i，其中 P_i = x_i·G，Y_i = d_i·G。
    std::string compute_derived_public(const std::string& point_hex);

    /// @brief 合成完整公钥 PK_i = P_i + Y_i（椭圆曲线点的加法）
    ///
    /// 将用户的静态公钥 P_i 与派生公钥 Y_i 在椭圆曲线上相加。
    ///
    /// @param public_hex 用户静态公钥 P_i 的十六进制字符串（130字符）
    /// @param derived_public_hex 派生公钥 Y_i 的十六进制字符串（130字符）
    /// @return 完整公钥 PK_i = P_i + Y_i 的130字符十六进制字符串
    ///
    /// @note 由于椭圆曲线上点的加法满足：PK_i = P_i + Y_i = x_i·G + d_i·G = (x_i + d_i)·G = sk_i·G，
    ///       因此完整公钥与完整私钥 sk_i 保持正确的配对关系。
    ///       在密钥协商中，对端需要知道己方的完整公钥才能验证签名。
    std::string derive_full_public(const std::string& public_hex, const std::string& derived_public_hex);

    // ========================================================================
    //                          Schnorr 签名与验证
    // ========================================================================

    /// @brief 对协商报文执行 Schnorr 签名
    ///
    /// 签名流程（Schnorr 签名方案）：
    /// 1. 生成随机临时标量 k ← Z_n^*
    /// 2. 计算临时公钥点 R = k · G
    /// 3. 构建碰撞抵抗的 transcript（RA || ID || WB || T）
    /// 4. 计算挑战值 e = H(R || transcript) mod n（若 e = 0 则设为 1）
    /// 5. 计算 s = k + e · sk (mod n)
    /// 6. 返回签名 (R, s)
    ///
    /// @param ra_hex 发送方的临时公钥 RA 的十六进制字符串（130字符）
    /// @param id 发送方身份标识（如 "pile-001"）
    /// @param wb_hex 对端静态公钥 WB 的十六进制字符串（130字符）
    /// @param t 当前时间戳（ISO-8601 格式）
    /// @param full_private_hex 发送方的完整私钥 sk 的十六进制字符串（64字符）
    /// @return Signature 包含 (r_hex = R的编码, s_hex = s)，共194字符十六进制
    ///
    /// @note Schnorr 签名具有不可延展性（与 ECDSA 不同），
    ///       在 CL-PKC 密钥协商中使用可防止未知密钥共享攻击（UKS）。
    /// @warning 每次签名必须使用新的、不可预测的随机标量 k。
    ///          重复使用 k 将导致私钥泄露。
    Signature sign_transcript(const std::string& ra_hex, const std::string& id, const std::string& wb_hex,
                              const std::string& t, const std::string& full_private_hex);

    /// @brief 验证对端协商报文的 Schnorr 签名
    ///
    /// 验证流程：
    /// 1. 从 sig_hex 中分离 r_hex（前130字符）与 s_hex（后64字符）
    /// 2. 与签名相同的 transcript 计算挑战值 e = H(R || transcript) mod n
    /// 3. 计算 left = s · G
    /// 4. 计算 right = R + e · PK（PK 为对端完整公钥）
    /// 5. 比较 left == right（椭圆曲线点的相等）
    ///
    /// 正确性证明：
    /// left = s·G = (k + e·sk)·G = k·G + e·sk·G = R + e·PK = right ✓
    ///
    /// @param ra_hex 己方临时公钥 RA 的十六进制字符串（130字符）
    /// @param id 对端身份标识
    /// @param wb_hex 己方静态公钥 WB 的十六进制字符串（130字符）
    /// @param t 对端提供的时间戳
    /// @param sig_hex 待验证的签名十六进制字符串（194字符 = r_hex + s_hex）
    /// @param full_public_hex 对端的完整公钥 PK 的十六进制字符串（130字符）
    /// @return true 签名有效；false 签名无效（可能是篡改、重放或身份冒充）
    ///
    /// @note 验证失败时不会抛出异常，而是返回 false，
    ///       调用方应根据返回值决定是否继续后续密钥协商流程。
    bool verify_transcript(const std::string& ra_hex, const std::string& id, const std::string& wb_hex,
                           const std::string& t, const std::string& sig_hex, const std::string& full_public_hex);

    // ========================================================================
    //                          会话密钥派生
    // ========================================================================

    /// @brief 从 ECDH 共享秘密与绑定数据派生最终会话密钥
    ///
    /// 流程：
    /// 1. 使用己方临时私钥 × 对端临时公钥 计算 ECDH 共享点 S = a·B
    /// 2. 提取 S 的 x 坐标作为共享秘密的原材料
    /// 3. 将 x 坐标与以下绑定数据拼接：RA, RB, ID_A, ID_B, T_A, T_B
    /// 4. 对拼接后的数据进行 SHA-256 哈希，输出会话密钥
    ///
    /// @param eph_secret_hex 己方临时私钥 a 的十六进制（64字符）
    /// @param peer_point_hex 对端临时公钥 B 的十六进制（130字符）
    /// @param ra_hex 己方临时公钥 RA 的十六进制（130字符）
    /// @param rb_hex 对端临时公钥 RB 的十六进制（130字符）
    /// @param ida 己方身份标识
    /// @param idb 对端身份标识
    /// @param ta 己方时间戳
    /// @param tb 对端时间戳
    /// @return 会话密钥的64字符十六进制字符串（SHA-256 输出）
    ///
    /// @note 此派生方式绑定了完整的协议上下文，确保即使 ECDH 共享秘密被
    ///       某种方式泄露（如临时私钥不完美随机），攻击者也无法伪造带有
    ///       不同身份的会话密钥。
    /// @note 此函数设计为对称调用：双方使用各自的临时私钥和对端的临时公钥，
    ///       配合相同的绑定数据，应得到相同的会话密钥。
    std::string derive_session_key(const std::string& eph_secret_hex, const std::string& peer_point_hex,
                                   const std::string& ra_hex, const std::string& rb_hex,
                                   const std::string& ida, const std::string& idb,
                                   const std::string& ta, const std::string& tb);

    // ========================================================================
    //                          通用密码学原语
    // ========================================================================

    /// @brief 计算 HMAC-SHA256 并以十六进制返回
    ///
    /// @param key_hex HMAC 密钥的十六进制字符串
    /// @param data_hex 待认证数据的十六进制字符串
    /// @return HMAC-SHA256 结果的十六进制字符串（64字符）
    ///
    /// @note 用于充电桩与云端之间的预共享密钥身份认证挑战-响应。
    ///       Cloud 发送随机 nonce，充电桩用预共享密钥计算 HMAC 回送，
    ///       以此证明自己是合法设备。
    std::string hmac_sha256_hex(const std::string& key_hex, const std::string& data_hex);

    /// @brief ECIES 解密：使用 AES-256-GCM 对称解密，密钥由 ECDH 派生
    ///
    /// 密文格式（二进制字节）：
    /// [临时公钥 R (65字节)][GCM Nonce (12字节)][密文载荷][GCM Tag (16字节)]
    ///
    /// 解密流程：
    /// 1. 解析密文，提取 R、nonce、密文、tag 四个部分
    /// 2. 使用己方私钥 × 临时公钥 R 计算 ECDH 共享点 S = sk · R
    /// 3. 提取 S 的 x 坐标，SHA-256 后作为 AES-256-GCM 的对称密钥
    /// 4. 使用 AES-256-GCM 解密并验证 tag
    ///
    /// @param ciphertext_hex 完整密文的十六进制字符串
    /// @param secret_hex 己方私钥的十六进制字符串（64字符）
    /// @return 解密后明文的十六进制字符串
    /// @throws std::runtime_error 密文长度不足、解密失败或 tag 验证失败
    ///
    /// @note 此函数用于解密 KGC 通过 Cloud 透传的部分私钥。
    ///       KGC 使用充电桩的静态公钥 P_i 加密，只有持有对应私钥 x_i
    ///       的充电桩才能解密，从而确保部分私钥的机密性。
    /// @warning GCM tag 验证失败说明密文可能被篡改，此时不应使用解密结果。
    std::string ecies_decrypt(const std::string& ciphertext_hex, const std::string& secret_hex);

private:
    EC_GROUP* group_;   ///< secp256r1 (NIST P-256) 椭圆曲线群结构
    BN_CTX* ctx_;       ///< OpenSSL 大数运算上下文，用于加速模运算
    BIGNUM* order_;     ///< 曲线阶 n（群中点的总数/标量的模数）

    // -----------------------------------------------------------------------
    // 格式转换辅助函数
    // -----------------------------------------------------------------------

    /// @brief 将 BIGNUM 转换为64字符固定长度十六进制字符串（不足时左补零）
    /// @param bn 待转换的大整数
    /// @return 64字符固定宽度小写十六进制字符串
    /// @note 用于确保所有标量（私钥、签名分量等）输出格式一致
    std::string bn_to_fixed_hex(const BIGNUM* bn) const;

    /// @brief 将十六进制字符串解析为 BIGNUM
    /// @param hex 十六进制字符串（大小写均可）
    /// @return 新分配的大整数指针（调用方负责用 BN_free 释放）
    BIGNUM* hex_to_bn(const std::string& hex) const;

    /// @brief 将十六进制字符串转换为原始字节向量
    /// @param hex 十六进制字符串（2字符 = 1字节）
    /// @return 原始字节向量
    std::vector<unsigned char> hex_to_bytes(const std::string& hex) const;

    /// @brief 将原始字节向量转换为十六进制字符串
    /// @param data 原始字节向量
    /// @return 小写十六进制字符串（2字符/字节）
    std::string bytes_to_hex(const std::vector<unsigned char>& data) const;

    // -----------------------------------------------------------------------
    // 哈希与密码学辅助函数
    // -----------------------------------------------------------------------

    /// @brief 计算数据的 SHA-256 摘要
    /// @param data 原始字节数据
    /// @return 32字节（256位）SHA-256 摘要
    std::vector<unsigned char> sha256(const std::vector<unsigned char>& data) const;

    /// @brief 构建碰撞抵抗的 transcript 缓冲区
    ///
    /// 格式（每项为 长度(2字节大端) || 数据）：
    /// len(RA) || RA || len(ID) || ID || len(WB) || WB || len(T) || T
    ///
    /// 使用长度前缀的目的是消除各字段之间的边界模糊性，
    /// 防止存在性伪造攻击（例如 "AB"+"C" 与 "A"+"BC" 产生相同哈希输入）。
    ///
    /// @param ra_hex 临时公钥 RA
    /// @param id 身份标识
    /// @param wb_hex 对端静态公钥
    /// @param t 时间戳
    /// @return 构建好的 transcript 字节序列
    std::vector<unsigned char> transcript(const std::string& ra_hex, const std::string& id,
                                          const std::string& wb_hex, const std::string& t) const;

    /// @brief H2 哈希函数：将椭圆曲线点映射为群阶内的标量
    ///
    /// 计算 steps：
    /// 1. 跳过 SEC1 的第一个字节（0x04标识），提取坐标字节
    /// 2. 对坐标字节计算 SHA-256
    /// 3. 将摘要转换为 BIGNUM 并对 order_ 取模
    /// 4. 若结果为 0，则置为 1（避免退化密钥）
    ///
    /// @param point_hex 椭圆曲线点的 SEC1 非压缩编码十六进制（130字符）
    /// @return 映射后的标量，64字符固定长度十六进制
    ///
    /// @note H2 是 CL-PKC 标准中的第二个密码学哈希函数，
    ///       用于将椭圆曲线点映射为群阶内的标量值。
    ///       即使输入点因攻击被精心选择，SHA-256 的碰撞抵抗性
    ///       也保证了映射的安全性。
    std::string hash_point_to_scalar(const std::string& point_hex) const;

    // -----------------------------------------------------------------------
    // 椭圆曲线点序列化/反序列化
    // -----------------------------------------------------------------------

    /// @brief 将 EC_POINT 序列化为 SEC1 非压缩字节格式（0x04 || X || Y，65字节）
    /// @param point 椭圆曲线点指针
    /// @return SEC1 非压缩编码的字节向量（65字节）
    std::vector<unsigned char> point_to_bytes(const EC_POINT* point) const;

    /// @brief 将十六进制 SEC1 编码反序列化为 EC_POINT
    /// @param hex 椭圆曲线点的十六进制编码字符串
    /// @return 新分配的 EC_POINT 指针（调用方负责用 EC_POINT_free 释放）
    EC_POINT* point_from_hex(const std::string& hex) const;

    /// @brief 在 [1, order_-1] 范围内生成密码学安全的随机标量
    ///
    /// 使用 BN_rand_range 生成随机数，若结果为0则重试，
    /// 确保标量非零（零标量对应的公钥为无穷远点，不安全）。
    ///
    /// @return 新分配的 BIGNUM 指针（调用方负责用 BN_free 释放）
    BIGNUM* random_scalar() const;
};
