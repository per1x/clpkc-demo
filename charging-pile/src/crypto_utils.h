#pragma once

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <string>
#include <vector>

// ============================================================================
// @file crypto_utils.h
// @brief CL-PKC 充电桩密码学工具（国密 SM2/SM3，隐式证书方案，OpenSSL）。
//
// 与 Java 侧（BouncyCastle）实现字节级对齐：
//   - 曲线 SM2；点线上编码 x(32)‖y(32)（128 hex，无 04 前缀）；
//   - 完整私钥 dA = (tA + ua) mod n；完整公钥 PA = WA + λ·Ppub；
//     HA = SM3(0x0100‖ID32‖a‖b‖Gx‖Gy‖PpubX‖PpubY)，λ = SM3(WAx‖WAy‖HA)；
//   - 部分私钥用标准 SM2 公钥加密（C1C3C2 原始拼接，C1 含 04，共 129 字节），此处手动解密；
//   - 会话签名用标准 SM2 数字签名（线上裸 r‖s 64 字节，32 字节 ID 作 ZA 用户标识，ENTL=0x0100）；
//   - 会话密钥 SK = SM3(Sx‖R_A‖R_B‖ID_A‖ID_B‖nonce)，单次 SM3 出 32 字节。
//   - **编码总则：所有进哈希/签名的字段一律用「解码后的原始字节」，不用 hex 文本**；
//     进哈希字节数：点 64、ID 32、nonce 16、Sx 32。
//   - ID 为 32 字节，线上/接口传 64 字符 hex：桩 ID_B = 7 字节 BCD 主机编号 ‖ 25 字节 0x00；
//     云 ID_A = 域名 ASCII ‖ 0x00 补齐到 32 字节。
// ============================================================================

struct KeyMaterial {
    std::string secret_hex;  // 私钥标量，64 字符 hex
    std::string public_hex;  // 公钥点，x‖y，128 字符 hex
};

class CryptoUtils {
public:
    CryptoUtils();
    ~CryptoUtils();

    CryptoUtils(const CryptoUtils&) = delete;
    CryptoUtils& operator=(const CryptoUtils&) = delete;

    // ---- ID 构造（ID 一律 32 字节；线上/接口一律传 64 字符 hex）----
    // 桩 ID_B：7 字节 BCD 主机编号 ‖ 25 字节 0x00。
    //   host_no_decimal 为十进制数字串（≤14 位），不足 14 位**左侧补 '0'**（保持数值不变）。
    static std::string id_hex_from_bcd(const std::string& host_no_decimal);
    // 云 ID_A：域名 ASCII 字节 ‖ 0x00 补齐到 32 字节。
    static std::string id_hex_from_ascii(const std::string& ascii);

    KeyMaterial generate_static_key();
    // dA = (tA + ua) mod n（tA 来自 SM2 解密的部分私钥密文）
    std::string compose_full_private(const std::string& secret_hex, const std::string& encrypted_partial_hex);
    // PA = WA + λ·Ppub（id_hex = 32 字节 ID 的 64 字符 hex）
    std::string reconstruct_full_public(const std::string& id_hex, const std::string& claimed_public_hex,
                                        const std::string& master_public_hex);

    // 发起方（桩）签名 transcript = R_B ‖ ID_B ‖ W_B ‖ nonce
    std::string sign_initiator(const std::string& r_pile_hex, const std::string& id_hex,
                               const std::string& w_hex, const std::string& nonce,
                               const std::string& full_private_hex);
    // 验响应方（云）签名 transcript = R_A ‖ R_B ‖ ID_A ‖ W_A ‖ nonce
    bool verify_responder(const std::string& r_a_hex, const std::string& r_b_hex,
                          const std::string& id_hex, const std::string& w_hex, const std::string& nonce,
                          const std::string& sig_raw_hex, const std::string& full_public_hex);

    // 生成 n 字节随机数并返回 hex（握手 nonce 用，CSPRNG）
    std::string random_bytes_hex(int n_bytes);

    std::string derive_session_key(const std::string& eph_secret_hex, const std::string& peer_point_hex,
                                   const std::string& ra_hex, const std::string& rb_hex,
                                   const std::string& ida_hex, const std::string& idb_hex,
                                   const std::string& nonce);

    std::string hmac_sm3_hex(const std::string& key_hex, const std::string& data_hex);
    // 常量时间校验 HMAC-SM3（第一阶段双向挑战应答，验云端 MAC 用）
    bool hmac_sm3_verify(const std::string& key_hex, const std::string& data_hex,
                         const std::string& expected_mac_hex);
    std::string sm3_hex(const std::string& data_hex) const;

private:
    // 手动 SM2 C1C3C2 解密（明文返回 hex）
    std::string sm2_decrypt_c1c3c2(const std::string& cipher_hex, const std::string& secret_hex);
    std::vector<unsigned char> compute_ha(const std::vector<unsigned char>& id32,
                                          const std::string& master_public_hex) const;
    // λ = SM3(WAx‖WAy‖HA) 作大整数
    BIGNUM* compute_lambda(const EC_POINT* wa, const std::vector<unsigned char>& ha) const;

    // 通用：把有序定长字节字段直接拼接（无长度前缀）
    static std::vector<unsigned char> build_transcript(const std::vector<std::vector<unsigned char>>& fields);
    // SM2 签名/验签核心（对已构造好的 msg 操作，32 字节 ID 作 ZA，ENTL=0x0100）
    std::string sm2_sign(const std::vector<unsigned char>& msg, const std::vector<unsigned char>& id32,
                         const std::string& full_private_hex);
    bool sm2_verify(const std::vector<unsigned char>& msg, const std::vector<unsigned char>& id32,
                    const std::string& sig_raw_hex, const std::string& full_public_hex);

    // 点 ↔ x‖y（64 字节 / 128 hex），带曲线校验
    std::string point_to_xy_hex(const EC_POINT* point) const;
    EC_POINT* point_from_xy_hex(const std::string& hex) const;
    // 点 → SEC1 非压缩（04‖x‖y），供 EVP 建 SM2 公钥用
    std::vector<unsigned char> point_to_sec1(const EC_POINT* point) const;
    std::vector<unsigned char> coord_bytes(const BIGNUM* v) const;  // 定长 32

    std::string bn_to_fixed_hex(const BIGNUM* bn) const;
    BIGNUM* hex_to_bn(const std::string& hex) const;
    std::vector<unsigned char> hex_to_bytes(const std::string& hex) const;
    // 定长解码：字节数不符立即报错（transcript/KDF 入参校验用）
    std::vector<unsigned char> hex_fixed(const std::string& hex, std::size_t want,
                                         const char* name) const;
    std::string bytes_to_hex(const std::vector<unsigned char>& data) const;
    std::vector<unsigned char> sm3(const std::vector<unsigned char>& data) const;
    BIGNUM* random_scalar() const;

    EC_GROUP* group_;
    BN_CTX* ctx_;
    BIGNUM* order_;
};
