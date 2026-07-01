#pragma once

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <string>
#include <vector>

// ============================================================================
// @file crypto_utils.h
// @brief CL-PKC 充电桩密码学工具（OpenSSL secp256r1）。
//
// 与 Java clpkc-core 字节级对齐：SEC1 非压缩点编码；H2 = SHA256(X||Y) mod n；
// Schnorr 挑战 e = SHA256(R || transcript) mod n；transcript 为 4 段
// len(2B BE)||bytes，依次 (ra, id, wb, nonce)；会话密钥
// = SHA256(x(ECDH) || ra || rb || idA || idB || nonce)。
//
// 生产化改造：去除时间戳，改用握手 nonce 绑定；点解码强制校验在曲线上
// （抵御无效曲线攻击）。
// ============================================================================

struct KeyMaterial {
    std::string secret_hex;  // 私钥标量，64 字符 hex
    std::string public_hex;  // 公钥点，SEC1 非压缩，130 字符 hex
};

struct Signature {
    std::string r_hex;  // R 点，130 字符 hex
    std::string s_hex;  // 标量 s，64 字符 hex
    std::string to_hex() const { return r_hex + s_hex; }
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

    // Schnorr（transcript 第 4 段为 nonce）
    Signature sign_transcript(const std::string& ra_hex, const std::string& id,
                              const std::string& wb_hex, const std::string& nonce,
                              const std::string& full_private_hex);
    bool verify_transcript(const std::string& ra_hex, const std::string& id,
                           const std::string& wb_hex, const std::string& nonce,
                           const std::string& sig_hex, const std::string& full_public_hex);

    // 会话密钥（绑定 nonce，无时间戳）
    std::string derive_session_key(const std::string& eph_secret_hex, const std::string& peer_point_hex,
                                   const std::string& ra_hex, const std::string& rb_hex,
                                   const std::string& ida, const std::string& idb,
                                   const std::string& nonce);

    std::string hmac_sha256_hex(const std::string& key_hex, const std::string& data_hex);
    std::string ecies_decrypt(const std::string& ciphertext_hex, const std::string& secret_hex);

    // 对 ASCII 字符串按其字节做 SHA-256，返回十六进制。用于会话密钥指纹（单向）。
    std::string sha256_hex_of_ascii(const std::string& ascii) const;

private:
    std::string hash_point_to_scalar(const std::string& point_hex) const;
    std::vector<unsigned char> transcript(const std::string& ra_hex, const std::string& id,
                                          const std::string& wb_hex, const std::string& nonce) const;

    std::string bn_to_fixed_hex(const BIGNUM* bn) const;
    BIGNUM* hex_to_bn(const std::string& hex) const;
    std::vector<unsigned char> hex_to_bytes(const std::string& hex) const;
    std::string bytes_to_hex(const std::vector<unsigned char>& data) const;
    std::vector<unsigned char> sha256(const std::vector<unsigned char>& data) const;
    std::vector<unsigned char> point_to_bytes(const EC_POINT* point) const;
    // 解码 SEC1 点并校验在曲线上；失败抛 std::runtime_error。
    EC_POINT* point_from_hex(const std::string& hex) const;
    BIGNUM* random_scalar() const;

    EC_GROUP* group_;
    BN_CTX* ctx_;
    BIGNUM* order_;
};
