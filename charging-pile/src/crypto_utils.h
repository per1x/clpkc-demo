#pragma once

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <string>
#include <vector>

// ============================================================================
// @file crypto_utils.h
// @brief CL-PKC 充电桩密码学工具（国密 SM2/SM3，OpenSSL）。
//
// 与 Java clpkc-core（BouncyCastle）字节级对齐：
//   - 曲线 SM2（NID_sm2），SEC1 非压缩点编码；
//   - H2 = SM3(X||Y) mod n；
//   - 部分私钥用标准 SM2 公钥加密，密文 ASN.1 DER；
//   - 无证书签名用标准 SM2 数字签名（DER），签名方 id 作为 ZA 的用户标识；
//   - 挑战-响应用 HMAC-SM3；
//   - 会话密钥 = SM3(x(ECDH) || ra || rb || idA || idB || nonce)。
//
// 防重放仅用握手 nonce（无时间戳）。点解码强制校验在曲线上。
// ============================================================================

struct KeyMaterial {
    std::string secret_hex;  // 私钥标量，64 字符 hex
    std::string public_hex;  // 公钥点，SEC1 非压缩，130 字符 hex
};

class CryptoUtils {
public:
    CryptoUtils();
    ~CryptoUtils();

    CryptoUtils(const CryptoUtils&) = delete;
    CryptoUtils& operator=(const CryptoUtils&) = delete;

    KeyMaterial generate_static_key();
    std::string compose_full_private(const std::string& secret_hex, const std::string& partial_hex);
    std::string compute_derived_public(const std::string& point_hex);
    std::string derive_full_public(const std::string& public_hex, const std::string& derived_public_hex);

    // SM2 数字签名（返回 DER 签名 hex；id 为签名方标识，用于 ZA）
    std::string sign_transcript(const std::string& ra_hex, const std::string& id,
                                const std::string& wb_hex, const std::string& nonce,
                                const std::string& full_private_hex);
    bool verify_transcript(const std::string& ra_hex, const std::string& id,
                           const std::string& wb_hex, const std::string& nonce,
                           const std::string& sig_der_hex, const std::string& full_public_hex);

    // 会话密钥（SM3，绑定 nonce，无时间戳）
    std::string derive_session_key(const std::string& eph_secret_hex, const std::string& peer_point_hex,
                                   const std::string& ra_hex, const std::string& rb_hex,
                                   const std::string& ida, const std::string& idb,
                                   const std::string& nonce);

    std::string hmac_sm3_hex(const std::string& key_hex, const std::string& data_hex);
    // SM2 解密（输入 ASN.1 DER 密文 hex），返回明文 hex
    std::string sm2_decrypt(const std::string& ciphertext_der_hex, const std::string& secret_hex);
    // 对 ASCII 串按字节做 SM3，返回 hex（用于会话密钥指纹）
    std::string sm3_hex_of_ascii(const std::string& ascii) const;

private:
    std::string hash_point_to_scalar(const std::string& point_hex) const;
    std::vector<unsigned char> transcript(const std::string& ra_hex, const std::string& id,
                                          const std::string& wb_hex, const std::string& nonce) const;

    std::string bn_to_fixed_hex(const BIGNUM* bn) const;
    BIGNUM* hex_to_bn(const std::string& hex) const;
    std::vector<unsigned char> hex_to_bytes(const std::string& hex) const;
    std::string bytes_to_hex(const std::vector<unsigned char>& data) const;
    std::vector<unsigned char> sm3(const std::vector<unsigned char>& data) const;
    std::vector<unsigned char> point_to_bytes(const EC_POINT* point) const;
    EC_POINT* point_from_hex(const std::string& hex) const;
    BIGNUM* random_scalar() const;

    EC_GROUP* group_;
    BN_CTX* ctx_;
    BIGNUM* order_;
};
