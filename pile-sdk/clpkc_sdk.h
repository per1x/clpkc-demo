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
// 约定（详见 README.md，与 Java 云端实现逐字节一致）：
//   - 所有入参/返回值均为 **hex 字符串**（输入大小写不敏感，输出一律小写）。
//   - **统一规则：所有进哈希/签名的字段一律使用「解码后的原始字节」，绝不使用 hex 文本。**
//     进哈希时各字段字节数：曲线点 64、ID 32、nonce 16、Sx 32、签名 r‖s 各 32。
//   - 曲线点：64 字节裸 X‖Y（128 hex，**不含 04 前缀**）。
//   - 标量/私钥：32 字节（64 hex）。
//   - 签名：64 字节裸 r‖s（128 hex，**非 DER**）。
//   - ID：**32 字节**（64 hex），HA / ZA / transcript / KDF 四处统一，ENTL 恒为 0x0100（256 bit）。
//         桩 ID_B 用 make_id_from_bcd(主机编号)，云 ID_A 用 make_id_from_ascii(域名)。
//   - nonce：以 hex 字符串传入（16 字节 → 32 字符），内部一律 hex 解码为 **16 原始字节**
//         后参与 transcript / KDF / HMAC（三处一致）。长度不符直接报错。
//   - SM2 密文：C1C3C2 原始拼接，C1 含 04 前缀，共 129 字节（258 hex）。
//   - HMAC-SM3 输出 32 字节；第一阶段 random_A/random_B 各 16 字节。
//   - 会话密钥 SK = SM3(Sx ‖ R_A ‖ R_B ‖ ID_A ‖ ID_B ‖ nonce)，32 字节；
//     SM4 密钥取 SK 前 16 字节。
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

struct KeyMaterial {
    std::string secret_hex;  // 私钥标量 d，32 字节 / 64 hex
    std::string public_hex;  // 公钥点 x‖y，64 字节 / 128 hex
};

// ---------------------------------------------------------------------------
// 1. 密钥与随机数
// ---------------------------------------------------------------------------

// 生成 SM2 密钥对：私钥取 [1,n-1] 内的 CSPRNG 随机数，公钥 = d·G。
// 长期密钥 (d_B, U_B) 与每次会话的临时密钥 (b, R_B) 都用此函数。失败抛 Error。
KeyMaterial generate_static_key();

// CSPRNG 随机字节 → 2*n_bytes 个 hex。n_bytes 必须 > 0，否则抛 Error。
// nonce 与 random_A / random_B 均传 16。
std::string random_bytes_hex(int n_bytes);

// ---------------------------------------------------------------------------
// 2. HMAC-SM3（第一阶段挑战应答用）
// ---------------------------------------------------------------------------

// HMAC-SM3(key, data)：两个入参均先 hex 解码为原始字节再计算，返回 64 hex / 32 字节。
// 本协议 key 为 16 字节预共享密钥，data 为 16 字节随机挑战。hex 非法抛 Error。
std::string hmac_sm3_hex(const std::string& key_hex, const std::string& data_hex);

// 常量时间比较校验 HMAC（防时序侧信道）。校验对端 MAC 必须用本函数。
// 不抛异常：不匹配或入参非法一律返回 false。
bool hmac_sm3_verify(const std::string& key_hex, const std::string& data_hex,
                     const std::string& expected_mac_hex);

// ---------------------------------------------------------------------------
// 3. 隐式证书：部分私钥解密 / 合成 / 公钥重建
// ---------------------------------------------------------------------------

// SM2 解密（C1C3C2）。d_hex：64 hex/32 字节本机私钥 u_B；
// cipher_hex：258 hex/129 字节部分私钥密文（C1 含 04）。返回明文 t 的 hex（64 hex/32 字节）。
// 单独暴露，便于区分是解密失败还是合成失败。长度/格式非法、C3 校验不过均抛 Error。
std::string sm2_decrypt(const std::string& d_hex, const std::string& cipher_hex);

// 合成完整私钥：先用 secret_hex 对 encrypted_partial_hex 做 SM2 解密得到 t，
// 再计算 SK = (d + t) mod n。secret_hex 64 hex/32 字节，encrypted_partial_hex 258 hex/129 字节，
// 返回 64 hex/32 字节。长度/格式非法或 C3 校验不过抛 Error。
// （若只想单独解密不合成，用 sm2_decrypt。）
std::string compose_full_private(const std::string& secret_hex,
                                 const std::string& encrypted_partial_hex);

// 重建完整公钥 PK = W + λ·Ppub，其中
//   HA = SM3(0x0100 ‖ ID32 ‖ a ‖ b ‖ Gx ‖ Gy ‖ Ppub.x ‖ Ppub.y)
//   λ  = SM3(W.x ‖ W.y ‖ HA)  （按大端无符号整数取用）
// id_hex 为 32 字节 ID 的 hex。
std::string reconstruct_full_public(const std::string& id_hex,
                                    const std::string& claimed_public_hex,
                                    const std::string& master_public_hex);

// 自检：验证 SK·G == W + λ·Ppub。开通流程落盘前应调用一次，确认密钥材料自洽。
// 入参：sk 64 hex，w / ppub 各 128 hex，id 64 hex。注意参数顺序与 reconstruct_full_public 不同。
// 不抛异常：不自洽或入参非法一律返回 false。
bool verify_keypair_consistency(const std::string& full_private_hex,
                                const std::string& claimed_public_hex,
                                const std::string& master_public_hex,
                                const std::string& id_hex);

// ---------------------------------------------------------------------------
// 4. 第二阶段：SM2 签名 / 验签（ZA 用 32 字节 ID，ENTL=0x0100）
// ---------------------------------------------------------------------------

// 发起方(主机)签名。transcript = R_B(64) ‖ ID_B(32) ‖ W_B(64) ‖ nonce(16)，共 176 字节，
// 各字段为原始字节、顺序直拼、无长度前缀。入参 rB/wB 各 128 hex，idB 64 hex，
// nonce 32 hex，sk 64 hex。返回 128 hex/64 字节裸 r‖s。
// SM2 签名含随机数 k，相同输入每次输出不同，判定以验签为准。入参非法抛 Error。
std::string sign_initiator(const std::string& r_pile_hex, const std::string& id,
                           const std::string& w_hex, const std::string& nonce,
                           const std::string& full_private_hex);

// 验响应方(云)签名。transcript = R_A(64) ‖ R_B(64) ‖ ID_A(32) ‖ W_A(64) ‖ nonce(16)，共 240 字节。
// sig_raw_hex 为 128 hex/64 字节裸 r‖s；pk_hex 为云端完整公钥（由 reconstruct_full_public 得到）。
// 不抛异常：验签不过或入参非法一律返回 false。
bool verify_responder(const std::string& r_a_hex, const std::string& r_b_hex,
                      const std::string& id, const std::string& w_hex,
                      const std::string& nonce, const std::string& sig_raw_hex,
                      const std::string& full_public_hex);

// 验发起方签名 —— 与 sign_initiator 配对，供集成方离线自检与联调定位。
// 参数含义同 sign_initiator，另加 sig_raw_hex(128 hex) 与 pk_hex(128 hex)。
// 不抛异常：验签不过或入参非法一律返回 false。
bool verify_initiator(const std::string& r_pile_hex, const std::string& id,
                      const std::string& w_hex, const std::string& nonce,
                      const std::string& sig_raw_hex, const std::string& full_public_hex);

// ---------------------------------------------------------------------------
// 5. 会话密钥
// ---------------------------------------------------------------------------

// SK = SM3(Sx(32) ‖ R_A(64) ‖ R_B(64) ‖ ID_A(32) ‖ ID_B(32) ‖ nonce(16))，共 240 字节输入，
// 单次 SM3，返回 64 hex/32 字节。Sx = 本方临时私钥 × 对端临时公钥 所得点的 X 坐标。
// 桩端固定传 eph_secret=b(自己的临时私钥)、peer_point=R_A(云临时公钥)；
// 而 rA/rB 与 idA/idB 无论哪一端都按「云在前、桩在后」传入。入参非法抛 Error。
std::string derive_session_key(const std::string& eph_secret_hex, const std::string& peer_point_hex,
                               const std::string& ra_hex, const std::string& rb_hex,
                               const std::string& ida_hex, const std::string& idb_hex,
                               const std::string& nonce);

// 会话密钥 → SM4 密钥：取 SK 的前 16 字节。入参 64 hex/32 字节，返回 32 hex/16 字节。
// 长度不符抛 Error。
std::string session_key_to_sm4(const std::string& sk32_hex);

// ---------------------------------------------------------------------------
// 6. 编码辅助
// ---------------------------------------------------------------------------

// 【云 ID_A】域名等 ASCII 字符串 → 32 字节 ID hex（右侧补 0x00；超 32 字节抛异常）。
//   例：make_id_from_ascii("cloud.example.com")
//       → 636c6f75642e6578616d706c652e636f6d + 15 个 00
std::string make_id_from_ascii(const std::string& ascii);

// 【桩 ID_B】主机编号（≤14 位十进制数字串）→ 32 字节 ID hex：
//   7 字节 BCD 主机编号 ‖ 25 字节 0x00。不足 14 位**左侧补 '0'**（保持数值不变）。
//   例：make_id_from_bcd("1") == make_id_from_bcd("00000000000001")
//       → 00000000000001 + 25 个 00
std::string make_id_from_bcd(const std::string& host_no_decimal);

// 点编码互转（只做格式转换，不做曲线校验；长度不符抛 Error）：
//   point_to_wire  : 接受 130 hex(65 字节 SEC1 04‖X‖Y) 或 128 hex(64 字节裸点)
//                    → 统一输出 128 hex 的 64 字节裸点（本协议线上格式）。
//   point_from_wire: 接受 128 hex 的 64 字节裸点 → 输出 130 hex 的 SEC1(04‖X‖Y)。
std::string point_to_wire(const std::string& point_hex);
std::string point_from_wire(const std::string& wire_hex);

// SM3 摘要：对传入字符串的**原始字节**做 SM3（不做 hex 解码），返回 64 hex/32 字节。
std::string sm3_hex_of_ascii(const std::string& ascii);

}  // namespace clpkc
