#pragma once

#include <stdexcept>
#include <string>

// ============================================================================
// CL-PKC 桩端(主机端) 密码学 SDK —— 国密 SM2/SM3/HMAC-SM3，隐式证书(ECQV/SM2 风格)。
//
// 定位：**只提供密码学算法**。纯函数、无状态、线程安全。
//   本 SDK 不含：文件/keystore 存储、网络通信、报文封装/解析、流程编排、重试超时。
//   这些由集成方(主机端应用)自行实现。
//
// 约定（详见 README.md，与现网 Java 云端实现逐字节一致）：
//   - 所有入参/返回值均为 **hex 字符串**（输入大小写不敏感，输出一律小写）。
//   - 曲线点：64 字节裸 X‖Y（128 hex，**不含 04 前缀**）。
//   - 标量/私钥：32 字节（64 hex）。
//   - 签名：64 字节裸 r‖s（128 hex，**非 DER**）。
//   - ID：**32 字节**（64 hex），不足右侧补 0x00；HA / ZA / transcript / KDF 四处统一，
//         ENTL 恒为 0x0100（256 bit）。用 make_id_from_ascii / make_id_from_bcd 构造。
//   - **统一规则：所有进哈希/签名的字段一律使用「解码后的原始字节」，绝不使用 hex 文本。**
//   - nonce：以 hex 字符串传入（16 字节 → 32 字符），内部一律 hex 解码为 **16 原始字节**
//         后参与 transcript / KDF / HMAC（三处一致）。长度不符直接报错。
//   - SM2 密文：C1C3C2 原始拼接，C1 含 04 前缀，共 129 字节（258 hex）。
//
// 错误处理：
//   - 入参非法/内部失败 → 抛 clpkc::Error（派生自 std::runtime_error）。
//   - verify_* 系列**不抛异常**：签名不匹配或入参格式非法一律返回 false。
//
// 依赖：仅 OpenSSL 3.x（需含 SM2/SM3）。
// ============================================================================

namespace clpkc {

class Error : public std::runtime_error {
public:
    explicit Error(const std::string& what) : std::runtime_error(what) {}
};

struct KeyPair {
    std::string secret_hex;  // 私钥标量 d，32 字节 / 64 hex
    std::string public_hex;  // 公钥点 x‖y，64 字节 / 128 hex
};

// ---------------------------------------------------------------------------
// 1. 密钥与随机数
// ---------------------------------------------------------------------------

// 生成 SM2 密钥对。长期密钥 (d_B, U_B) 与临时密钥 (b, R_B) 共用此函数。
KeyPair generate_keypair();

// CSPRNG 随机字节 → hex（n_bytes 必须 > 0）。握手 nonce / random_A / random_B 用。
std::string random_bytes_hex(int n_bytes);

// ---------------------------------------------------------------------------
// 2. HMAC-SM3（第一阶段挑战应答用）
// ---------------------------------------------------------------------------

// HMAC-SM3(key, data)：key_hex / data_hex 均先 hex 解码为原始字节再计算。返回 32 字节 hex。
std::string hmac_sm3_hex(const std::string& key_hex, const std::string& data_hex);

// 常量时间比较校验 HMAC（防时序侧信道）。格式非法返回 false，不抛异常。
bool hmac_sm3_verify(const std::string& key_hex, const std::string& data_hex,
                     const std::string& expected_mac_hex);

// ---------------------------------------------------------------------------
// 3. 隐式证书：部分私钥解密 / 合成 / 公钥重建
// ---------------------------------------------------------------------------

// SM2 解密（C1C3C2，C1 含 04）。d_hex 为本机私钥(u_B)，cipher_hex 为 KGC 下发的部分私钥密文。
// 返回明文 t_B 的 hex。单独暴露以便定位问题。
std::string sm2_decrypt(const std::string& d_hex, const std::string& cipher_hex);

// 合成完整私钥 SK = (d + t) mod n。d_hex 为本机私钥 u_B，t_hex 为解密出的部分私钥 t_B。
std::string compose_full_private(const std::string& d_hex, const std::string& t_hex);

// 重建完整公钥 PK = W + λ·Ppub，其中
//   HA = SM3(0x0100 ‖ ID32 ‖ a ‖ b ‖ Gx ‖ Gy ‖ Ppub.x ‖ Ppub.y)
//   λ  = SM3(W.x ‖ W.y ‖ HA)  （按大端无符号整数取用）
// id_hex 为 32 字节 ID 的 hex。
std::string reconstruct_full_public(const std::string& id_hex, const std::string& w_hex,
                                    const std::string& ppub_hex);

// 自检：验证 SK·G == W + λ·Ppub。开通落地后建议调用一次，确认密钥对自洽。
bool verify_keypair_consistency(const std::string& sk_hex, const std::string& w_hex,
                                const std::string& ppub_hex, const std::string& id_hex);

// ---------------------------------------------------------------------------
// 4. 第二阶段：SM2 签名 / 验签（ZA 用 32 字节 ID，ENTL=0x0100）
// ---------------------------------------------------------------------------

// 发起方(主机)签名。transcript = R_B ‖ ID_B ‖ W_B ‖ nonce_ascii（全定长直拼、无长度前缀）。
// 返回 64 字节裸 r‖s 的 hex。注：SM2 签名含随机数 k，同样输入每次输出不同（属正常）。
std::string sign_initiator(const std::string& rB_hex, const std::string& idB_hex,
                           const std::string& wB_hex, const std::string& nonce_hex,
                           const std::string& sk_hex);

// 验响应方(云)签名。transcript = R_A ‖ R_B ‖ ID_A ‖ W_A ‖ nonce_ascii。
// sig_raw_hex 为 64 字节裸 r‖s。pk_hex 为云端完整公钥（由 reconstruct_full_public 得到）。
bool verify_responder(const std::string& rA_hex, const std::string& rB_hex,
                      const std::string& idA_hex, const std::string& wA_hex,
                      const std::string& nonce_hex, const std::string& sig_raw_hex,
                      const std::string& pk_hex);

// 【附加】验发起方签名 —— 与 sign_initiator 配对，供集成方离线自检/联调定位使用。
bool verify_initiator(const std::string& rB_hex, const std::string& idB_hex,
                      const std::string& wB_hex, const std::string& nonce_hex,
                      const std::string& sig_raw_hex, const std::string& pk_hex);

// ---------------------------------------------------------------------------
// 5. 会话密钥
// ---------------------------------------------------------------------------

// SK = SM3(Sx ‖ R_A ‖ R_B ‖ ID_A ‖ ID_B ‖ nonce_ascii)，单次 SM3，输出 32 字节 hex。
// Sx = 本方临时私钥 × 对端临时公钥 得到点的 X 坐标（32 字节）。
//   桩端调用：eph_secret=b(自己的临时私钥)，peer_point=R_A(云临时公钥)。
std::string derive_session_key(const std::string& eph_secret_hex, const std::string& peer_point_hex,
                               const std::string& rA_hex, const std::string& rB_hex,
                               const std::string& idA_hex, const std::string& idB_hex,
                               const std::string& nonce_hex);

// 会话密钥(32 字节) → SM4 密钥(16 字节)：**取前 16 字节**。
std::string session_key_to_sm4(const std::string& sk32_hex);

// ---------------------------------------------------------------------------
// 6. 编码辅助
// ---------------------------------------------------------------------------

// ASCII 主机编号 → 32 字节 ID hex（右侧补 0x00；超 32 字节抛异常）。
std::string make_id_from_ascii(const std::string& ascii);

// 7 字节 BCD 主机编号(14 hex) → 32 字节 ID hex（BCD 置于前 7 字节，其余补 0x00）。
// 与 make_id_from_ascii 二选一，**待与对方确认现网编号形态后选用**。
std::string make_id_from_bcd(const std::string& bcd_hex);

// 点编码互转：wire 格式 = 64 字节裸 X‖Y（无 04）。
//   point_to_wire  : 接受 65 字节 SEC1(04‖X‖Y) 或 64 字节裸点 → 统一输出 64 字节裸点。
//   point_from_wire: 接受 64 字节裸点 → 输出 65 字节 SEC1(04‖X‖Y)，供需要 SEC1 的库使用。
std::string point_to_wire(const std::string& point_hex);
std::string point_from_wire(const std::string& wire_hex);

// SM3 摘要：data_hex 先 hex 解码再计算，返回 32 字节 hex。
std::string sm3_hex(const std::string& data_hex);

}  // namespace clpkc
