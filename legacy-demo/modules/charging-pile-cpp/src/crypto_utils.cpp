#include "crypto_utils.h"

#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdexcept>

// ============================================================================
// @file crypto_utils.cpp
// @brief CL-PKC 充电桩演示 - 密码学工具类实现
//
// 本文件实现了 crypto_utils.h 中声明的所有密码学函数，
// 包括密钥生成、CL-PKC 部分私钥/完整密钥组装、Schnorr 签名/验签、
// ECDH 会话密钥派生、ECIES 解密、HMAC 以及各类格式转换辅助函数。
// ============================================================================

namespace {
// RAII 封装：自动调用 BN_free 释放 BIGNUM
using BnPtr = std::unique_ptr<BIGNUM, decltype(&BN_free)>;
// RAII 封装：自动调用 EC_POINT_free 释放 EC_POINT
using PointPtr = std::unique_ptr<EC_POINT, decltype(&EC_POINT_free)>;
}

// ---------------------------------------------------------------------------
// 构造与析构
// ---------------------------------------------------------------------------
CryptoUtils::CryptoUtils() {
    // 根据 NIST 名称创建 secp256r1 (P-256) 椭圆曲线群
    group_ = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    // 创建大数运算上下文，用于 BN_mod_add 等模运算
    ctx_ = BN_CTX_new();
    // 获取并缓存曲线的阶 n，后续所有模 n 运算都以此为模数
    order_ = BN_new();
    EC_GROUP_get_order(group_, order_, ctx_);
}

CryptoUtils::~CryptoUtils() {
    BN_free(order_);
    BN_CTX_free(ctx_);
    EC_GROUP_free(group_);
}

// ---------------------------------------------------------------------------
// 静态密钥生成
// ---------------------------------------------------------------------------
KeyMaterial CryptoUtils::generate_static_key() {
    // 1. 在 [1, n-1] 范围内生成密码学安全随机标量 x
    BnPtr x(random_scalar(), BN_free);
    // 2. 创建公钥点 EC_POINT，准备存储 P = x·G
    PointPtr p(EC_POINT_new(group_), EC_POINT_free);
    // 3. 标量乘法：P = x · G（第三个参数为标量，第四个为基点，nullptr 表示使用默认生成元）
    EC_POINT_mul(group_, p.get(), x.get(), nullptr, nullptr, ctx_);
    // 4. 返回密钥材料：私钥 x（64字符hex）、公钥 P（130字符SEC1非压缩hex）
    return {bn_to_fixed_hex(x.get()), bytes_to_hex(point_to_bytes(p.get()))};
}

// ---------------------------------------------------------------------------
// CL-PKC 密钥组装
// ---------------------------------------------------------------------------
std::string CryptoUtils::compose_full_private(const std::string& secret_hex, const std::string& partial_hex) {
    // 对部分私钥点执行 H2 哈希映射，得到标量 d_i
    std::string d_hex = hash_point_to_scalar(partial_hex);
    BnPtr x(hex_to_bn(secret_hex), BN_free);    // 用户静态私钥 x_i
    BnPtr d(hex_to_bn(d_hex), BN_free);         // 派生标量 d_i = H2(Q_partial)
    BnPtr out(BN_new(), BN_free);
    // sk_i = (x_i + d_i) mod n
    BN_mod_add(out.get(), x.get(), d.get(), order_, ctx_);
    return bn_to_fixed_hex(out.get());
}

std::string CryptoUtils::compute_derived_public(const std::string& point_hex) {
    // 通过 H2 将输入点映射为标量 d_i
    std::string d_hex = hash_point_to_scalar(point_hex);
    BnPtr d(hex_to_bn(d_hex), BN_free);
    PointPtr Y_i(EC_POINT_new(group_), EC_POINT_free);
    // Y_i = d_i · G（标量乘基点）
    EC_POINT_mul(group_, Y_i.get(), d.get(), nullptr, nullptr, ctx_);
    return bytes_to_hex(point_to_bytes(Y_i.get()));
}

// ---------------------------------------------------------------------------
// H2：将椭圆曲线点映射为标量
// ---------------------------------------------------------------------------
std::string CryptoUtils::hash_point_to_scalar(const std::string& point_hex) const {
    auto point_bytes = hex_to_bytes(point_hex);
    // 跳过 SEC1 非压缩格式第一个字节 0x04，仅保留坐标 (x || y) 64字节
    std::vector<unsigned char> coords(point_bytes.begin() + 1, point_bytes.end());
    // 对坐标字节执行 SHA-256
    auto digest = sha256(coords);
    // 将摘要转换为 BIGNUM
    BIGNUM* out = BN_bin2bn(digest.data(), static_cast<int>(digest.size()), nullptr);
    // 对阶 n 取模，确保标量在 [0, n-1] 范围内
    BN_mod(out, out, order_, ctx_);
    // 若结果为 0，设为 1，避免零标量（对应退化公钥/私钥）
    if (BN_is_zero(out)) { BN_one(out); }
    return bn_to_fixed_hex(out);
}

// ---------------------------------------------------------------------------
// 完整公钥合成
// ---------------------------------------------------------------------------
std::string CryptoUtils::derive_full_public(const std::string& public_hex, const std::string& derived_public_hex) {
    // 反序列化 P_i 和 Y_i
    PointPtr p(point_from_hex(public_hex), EC_POINT_free);
    PointPtr y(point_from_hex(derived_public_hex), EC_POINT_free);
    PointPtr full(EC_POINT_new(group_), EC_POINT_free);
    // 椭圆曲线点加法：PK_i = P_i + Y_i
    EC_POINT_add(group_, full.get(), p.get(), y.get(), ctx_);
    return bytes_to_hex(point_to_bytes(full.get()));
}

// ---------------------------------------------------------------------------
// Schnorr 签名（对密钥协商报文）
// ---------------------------------------------------------------------------
Signature CryptoUtils::sign_transcript(const std::string& ra_hex, const std::string& id, const std::string& wb_hex,
                                       const std::string& t, const std::string& full_private_hex) {
    BnPtr sk(hex_to_bn(full_private_hex), BN_free);  // 签名方完整私钥
    BnPtr k(random_scalar(), BN_free);               // 随机临时标量 k ← Z_n^*
    PointPtr r_point(EC_POINT_new(group_), EC_POINT_free);
    // R = k · G
    EC_POINT_mul(group_, r_point.get(), k.get(), nullptr, nullptr, ctx_);
    auto r_bytes = point_to_bytes(r_point.get());     // R 的 SEC1 编码（65字节）
    // 构建 transcript = length-prefixed (RA || ID || WB || T)
    auto tx = transcript(ra_hex, id, wb_hex, t);
    // 拼接 R || transcript 用于生成挑战值 e
    std::vector<unsigned char> input = r_bytes;
    input.insert(input.end(), tx.begin(), tx.end());
    auto digest = sha256(input);
    // 挑战值 e = H(R || transcript) mod n
    BnPtr e(BN_bin2bn(digest.data(), static_cast<int>(digest.size()), nullptr), BN_free);
    BN_mod(e.get(), e.get(), order_, ctx_);
    if (BN_is_zero(e.get())) { BN_one(e.get()); }     // 避免 e = 0
    BnPtr s(BN_new(), BN_free);
    // s = k + e · sk (mod n)
    BN_mod_mul(s.get(), e.get(), sk.get(), order_, ctx_);
    BN_mod_add(s.get(), k.get(), s.get(), order_, ctx_);
    return {bytes_to_hex(r_bytes), bn_to_fixed_hex(s.get())};
}

// ---------------------------------------------------------------------------
// Schnorr 验证
// ---------------------------------------------------------------------------
bool CryptoUtils::verify_transcript(const std::string& ra_hex, const std::string& id, const std::string& wb_hex,
                                    const std::string& t, const std::string& sig_hex, const std::string& full_public_hex) {
    // 解析签名：前130字符 = R 点（65字节hex），后64字符 = 标量 s
    const std::string r_hex = sig_hex.substr(0, 130);
    const std::string s_hex = sig_hex.substr(130);
    PointPtr r(point_from_hex(r_hex), EC_POINT_free);        // R
    PointPtr pk(point_from_hex(full_public_hex), EC_POINT_free); // PK（完整公钥）
    BnPtr s(hex_to_bn(s_hex), BN_free);                     // s
    // 重新构建相同的 transcript，计算挑战值 e
    auto tx = transcript(ra_hex, id, wb_hex, t);
    auto r_bytes = hex_to_bytes(r_hex);
    std::vector<unsigned char> input = r_bytes;
    input.insert(input.end(), tx.begin(), tx.end());
    auto digest = sha256(input);
    BnPtr e(BN_bin2bn(digest.data(), static_cast<int>(digest.size()), nullptr), BN_free);
    BN_mod(e.get(), e.get(), order_, ctx_);
    if (BN_is_zero(e.get())) { BN_one(e.get()); }
    // left = s · G
    PointPtr left(EC_POINT_new(group_), EC_POINT_free);
    PointPtr epk(EC_POINT_new(group_), EC_POINT_free);
    PointPtr right(EC_POINT_new(group_), EC_POINT_free);
    EC_POINT_mul(group_, left.get(), s.get(), nullptr, nullptr, ctx_);
    // epk = e · PK（e 倍完整公钥）
    EC_POINT_mul(group_, epk.get(), nullptr, pk.get(), e.get(), ctx_);
    // right = R + e · PK
    EC_POINT_add(group_, right.get(), r.get(), epk.get(), ctx_);
    // 验证：left == right ⇔ s·G == R + e·PK ⇔ 签名有效
    return EC_POINT_cmp(group_, left.get(), right.get(), ctx_) == 0;
}

// ---------------------------------------------------------------------------
// 会话密钥派生（ECDH + 绑定上下文）
// ---------------------------------------------------------------------------
std::string CryptoUtils::derive_session_key(const std::string& eph_secret_hex, const std::string& peer_point_hex,
                                            const std::string& ra_hex, const std::string& rb_hex,
                                            const std::string& ida, const std::string& idb,
                                            const std::string& ta, const std::string& tb) {
    // 1. ECDH：shared = a · B（己方临时私钥 × 对端临时公钥）
    BnPtr scalar(hex_to_bn(eph_secret_hex), BN_free);
    PointPtr peer(point_from_hex(peer_point_hex), EC_POINT_free);
    PointPtr shared(EC_POINT_new(group_), EC_POINT_free);
    EC_POINT_mul(group_, shared.get(), nullptr, peer.get(), scalar.get(), ctx_);
    // 提取共享点的 x 坐标作为密钥派生种子
    BIGNUM* x = BN_new();
    BIGNUM* y = BN_new();
    EC_POINT_get_affine_coordinates(group_, shared.get(), x, y, ctx_);
    std::vector<unsigned char> input = hex_to_bytes(bn_to_fixed_hex(x));
    BN_free(x);
    BN_free(y);
    // 2. 拼接绑定数据：RA, RB, ID_A, ID_B, T_A, T_B
    auto append_hex = [&](const std::string& hex) {
        auto bytes = hex_to_bytes(hex);
        input.insert(input.end(), bytes.begin(), bytes.end());
    };
    append_hex(ra_hex);
    append_hex(rb_hex);
    // 身份和时间戳以 UTF-8 字符串字节形式拼接
    input.insert(input.end(), ida.begin(), ida.end());
    input.insert(input.end(), idb.begin(), idb.end());
    input.insert(input.end(), ta.begin(), ta.end());
    input.insert(input.end(), tb.begin(), tb.end());
    // 3. SHA-256 派生最终会话密钥
    return bytes_to_hex(sha256(input));
}

// ---------------------------------------------------------------------------
// HMAC-SHA256
// ---------------------------------------------------------------------------
std::string CryptoUtils::hmac_sha256_hex(const std::string& key_hex, const std::string& data_hex) {
    auto key = hex_to_bytes(key_hex);
    auto data = hex_to_bytes(data_hex);
    unsigned int len = SHA256_DIGEST_LENGTH;
    std::vector<unsigned char> out(len);
    HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
         data.data(), data.size(), out.data(), &len);
    return bytes_to_hex(out);
}

// ---------------------------------------------------------------------------
// ECIES 解密（AES-256-GCM + ECDH 密钥派生）
// ---------------------------------------------------------------------------
std::string CryptoUtils::ecies_decrypt(const std::string& ciphertext_hex, const std::string& secret_hex) {
    auto blob = hex_to_bytes(ciphertext_hex);
    // 密文最小长度：R(65) + nonce(12) + tag(16) = 93字节（不含载荷）
    if (blob.size() < 65 + 12 + 16) {
        throw std::runtime_error("invalid ECIES ciphertext length");
    }
    // 拆解密文各部分
    auto r_bytes = std::vector<unsigned char>(blob.begin(), blob.begin() + 65);      // 临时公钥 R
    auto nonce = std::vector<unsigned char>(blob.begin() + 65, blob.begin() + 77);   // GCM nonce (12字节)
    auto ciphertext = std::vector<unsigned char>(blob.begin() + 77, blob.end() - 16); // 密文载荷
    auto tag = std::vector<unsigned char>(blob.end() - 16, blob.end());              // GCM 认证标签 (16字节)

    // 反序列化临时公钥 R
    PointPtr R(EC_POINT_new(group_), EC_POINT_free);
    EC_POINT_oct2point(group_, R.get(), r_bytes.data(), r_bytes.size(), ctx_);

    // ECDH 密钥派生：S = sk · R
    BnPtr x(hex_to_bn(secret_hex), BN_free);
    PointPtr S(EC_POINT_new(group_), EC_POINT_free);
    EC_POINT_mul(group_, S.get(), nullptr, R.get(), x.get(), ctx_);

    // 提取 S 的 x 坐标（32字节）作为 AES 密钥的种子
    BnPtr sx(BN_new(), BN_free);
    BnPtr sy(BN_new(), BN_free);
    EC_POINT_get_affine_coordinates(group_, S.get(), sx.get(), sy.get(), ctx_);
    std::vector<unsigned char> x_coord(32);
    BN_bn2binpad(sx.get(), x_coord.data(), 32);

    // SHA-256(x_coord) → AES-256 密钥
    auto key = sha256(x_coord);

    // AES-256-GCM 解密流程
    EVP_CIPHER_CTX* evp_ctx = EVP_CIPHER_CTX_new();
    if (!evp_ctx) {
        throw std::runtime_error("EVP_CIPHER_CTX_new failed");
    }
    int len = 0;
    std::vector<unsigned char> plaintext(ciphertext.size());
    // 初始化 GCM 解密上下文（算法 = AES-256-GCM）
    if (!EVP_DecryptInit_ex(evp_ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr)) {
        EVP_CIPHER_CTX_free(evp_ctx);
        throw std::runtime_error("EVP_DecryptInit_ex failed");
    }
    // 设置 GCM IV（nonce）长度 = 12 字节
    if (!EVP_CIPHER_CTX_ctrl(evp_ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce.size()), nullptr)) {
        EVP_CIPHER_CTX_free(evp_ctx);
        throw std::runtime_error("EVP_CIPHER_CTX_ctrl SET_IVLEN failed");
    }
    // 传入密钥和 nonce
    if (!EVP_DecryptInit_ex(evp_ctx, nullptr, nullptr, key.data(), nonce.data())) {
        EVP_CIPHER_CTX_free(evp_ctx);
        throw std::runtime_error("EVP_DecryptInit_ex key/nonce failed");
    }
    // 解密载荷
    if (!EVP_DecryptUpdate(evp_ctx, plaintext.data(), &len, ciphertext.data(), static_cast<int>(ciphertext.size()))) {
        EVP_CIPHER_CTX_free(evp_ctx);
        throw std::runtime_error("EVP_DecryptUpdate failed");
    }
    int plaintext_len = len;
    // 设置 GCM 认证标签（用于完整性验证）
    if (!EVP_CIPHER_CTX_ctrl(evp_ctx, EVP_CTRL_GCM_SET_TAG, static_cast<int>(tag.size()), tag.data())) {
        EVP_CIPHER_CTX_free(evp_ctx);
        throw std::runtime_error("EVP_CIPHER_CTX_ctrl SET_TAG failed");
    }
    // 完成解密并验证 tag：若 tag 不匹配，EVP_DecryptFinal_ex 返回 0
    if (!EVP_DecryptFinal_ex(evp_ctx, plaintext.data() + plaintext_len, &len)) {
        EVP_CIPHER_CTX_free(evp_ctx);
        throw std::runtime_error("EVP_DecryptFinal_ex failed: tag verification failed");
    }
    plaintext_len += len;
    EVP_CIPHER_CTX_free(evp_ctx);
    plaintext.resize(plaintext_len);
    return bytes_to_hex(plaintext);
}

// ============================================================================
// 格式转换辅助函数实现
// ============================================================================

// ---------------------------------------------------------------------------
// BIGNUM → 固定长度64字符十六进制（左补零）
// ---------------------------------------------------------------------------
std::string CryptoUtils::bn_to_fixed_hex(const BIGNUM* bn) const {
    char* hex = BN_bn2hex(bn);
    std::string s(hex);
    OPENSSL_free(hex);               // OpenSSL 分配的 hex 缓冲区必须用 OPENSSL_free 释放
    if (s.size() < 64) {
        // 不足64字符时在左侧补零，确保所有标量输出格式一致
        s.insert(0, 64 - s.size(), '0');
    }
    return s;
}

// ---------------------------------------------------------------------------
// 十六进制字符串 → BIGNUM
// ---------------------------------------------------------------------------
BIGNUM* CryptoUtils::hex_to_bn(const std::string& hex) const {
    BIGNUM* bn = nullptr;
    // BN_hex2bn 自动分配 BIGNUM 内存，调用方负责释放
    BN_hex2bn(&bn, hex.c_str());
    return bn;
}

// ---------------------------------------------------------------------------
// 十六进制字符串 → 字节向量
// ---------------------------------------------------------------------------
std::vector<unsigned char> CryptoUtils::hex_to_bytes(const std::string& hex) const {
    std::vector<unsigned char> out;
    out.reserve(hex.size() / 2);
    // 每2个十六进制字符解析为1个字节
    for (std::size_t i = 0; i < hex.size(); i += 2) {
        out.push_back(static_cast<unsigned char>(std::stoul(hex.substr(i, 2), nullptr, 16)));
    }
    return out;
}

// ---------------------------------------------------------------------------
// 字节向量 → 小写十六进制字符串
// ---------------------------------------------------------------------------
std::string CryptoUtils::bytes_to_hex(const std::vector<unsigned char>& data) const {
    static const char* digits = "0123456789abcdef";
    std::string out;
    out.reserve(data.size() * 2);
    for (unsigned char c : data) {
        // 高4位 → 低4位，分别映射为十六进制字符
        out.push_back(digits[c >> 4]);
        out.push_back(digits[c & 0x0f]);
    }
    return out;
}

// ---------------------------------------------------------------------------
// SHA-256 哈希
// ---------------------------------------------------------------------------
std::vector<unsigned char> CryptoUtils::sha256(const std::vector<unsigned char>& data) const {
    std::vector<unsigned char> out(SHA256_DIGEST_LENGTH);
    SHA256(data.data(), data.size(), out.data());
    return out;
}

// ---------------------------------------------------------------------------
// 碰撞抵抗 transcript 构建
// ---------------------------------------------------------------------------
std::vector<unsigned char> CryptoUtils::transcript(const std::string& ra_hex, const std::string& id,
                                                   const std::string& wb_hex, const std::string& t) const {
    auto ra = hex_to_bytes(ra_hex);
    auto wb = hex_to_bytes(wb_hex);
    std::vector<unsigned char> out;
    // 辅助 lambda：以大端2字节写入字段长度，防止字段边界歧义
    auto append_len = [&](std::size_t len) {
        out.push_back(static_cast<unsigned char>((len >> 8) & 0xff));
        out.push_back(static_cast<unsigned char>(len & 0xff));
    };
    // 格式：len(RA)||RA || len(ID)||ID || len(WB)||WB || len(T)||T
    append_len(ra.size());
    out.insert(out.end(), ra.begin(), ra.end());
    append_len(id.size());
    out.insert(out.end(), id.begin(), id.end());
    append_len(wb.size());
    out.insert(out.end(), wb.begin(), wb.end());
    append_len(t.size());
    out.insert(out.end(), t.begin(), t.end());
    return out;
}

// ---------------------------------------------------------------------------
// EC_POINT → SEC1 非压缩字节序列（0x04 || X || Y, 65字节）
// ---------------------------------------------------------------------------
std::vector<unsigned char> CryptoUtils::point_to_bytes(const EC_POINT* point) const {
    std::vector<unsigned char> out(65);
    // POINT_CONVERSION_UNCOMPRESSED 产生 0x04 前缀的非压缩编码
    size_t len = EC_POINT_point2oct(group_, point, POINT_CONVERSION_UNCOMPRESSED, out.data(), out.size(), ctx_);
    out.resize(len);
    return out;
}

// ---------------------------------------------------------------------------
// 十六进制 SEC1 编码 → EC_POINT
// ---------------------------------------------------------------------------
EC_POINT* CryptoUtils::point_from_hex(const std::string& hex) const {
    auto bytes = hex_to_bytes(hex);
    EC_POINT* point = EC_POINT_new(group_);
    // EC_POINT_oct2point 自动识别压缩/非压缩格式
    EC_POINT_oct2point(group_, point, bytes.data(), bytes.size(), ctx_);
    return point;
}

// ---------------------------------------------------------------------------
// 生成群阶内的密码学安全随机标量（非零）
// ---------------------------------------------------------------------------
BIGNUM* CryptoUtils::random_scalar() const {
    BIGNUM* out = BN_new();
    do {
        // BN_rand_range 生成 [0, order_-1] 范围内的均匀随机数
        BN_rand_range(out, order_);
    } while (BN_is_zero(out));  // 拒绝零标量（对应无穷远点公钥，不安全）
    return out;
}
