#include <cstdint>
#include <cstring>
#include <exception>
#include <stdexcept>
#include <string>
#include <vector>

#include "config.h"
#include "crypto_utils.h"
#include "frame.h"
#include "keystore.h"
#include "logging.h"
#include "net_client.h"

// ============================================================================
// CL-PKC 充电桩客户端（国密 SM2，隐式证书方案，两阶段，二进制帧）。
//
// 桩↔云一律二进制帧（见 docs/WIRE_PROTOCOL.md）；云↔KGC 仍 JSON/HTTPS。
// 第一阶段(provision，仅首次，类型 0x39/0x3A)：双向 HMAC-SM3 挑战应答（桩出 random_B、
//   云出 random_A，双方互验 MAC，任一侧失败即中止）→ 申请部分私钥 → 组合 dA → 本地持久化。
// 第二阶段(session，每次，类型 0x3B/0x3C)：SM2 签名的 ECDH 两步协商 + 双向回执 → 会话密钥。
// (类型,STEP) 唯一确定报文语义；nonce 由桩自生成、云复用不重新生成。
// ============================================================================

namespace {

// ID → 32 字节 ASCII 零补齐（与密码学层一致；超长截断）
std::vector<unsigned char> id32(const std::string& id) {
    std::vector<unsigned char> out(32, 0x00);
    std::size_t n = id.size() < 32 ? id.size() : 32;
    std::memcpy(out.data(), id.data(), n);
    return out;
}

// 32 字节零补齐 ID → 去尾 0x00 还原 ASCII 串
std::string id_from32(const std::vector<unsigned char>& b) {
    std::size_t n = b.size();
    while (n > 0 && b[n - 1] == 0x00) {
        n--;
    }
    return std::string(b.begin(), b.begin() + n);
}

void append(std::vector<unsigned char>& dst, const std::vector<unsigned char>& src) {
    dst.insert(dst.end(), src.begin(), src.end());
}

// 第一阶段：双向 HMAC-SM3 认证 + 申请无证书密钥对并落地（二进制帧）
void provision(const PileConfig& cfg, CryptoUtils& crypto) {
    KeyMaterial static_key = crypto.generate_static_key();  // (ua, UA)
    LOG_INFO("第一阶段: 本地公钥 UA = " + static_key.public_hex);

    NetClient net(cfg.connect_timeout_ms, cfg.read_timeout_ms);
    net.connect(cfg.cloud_host, cfg.cloud_port);
    auto host = frame::bcd7_from_id(cfg.pile_id);
    uint16_t seq = 1;

    // msg1 (0x39/0x11 hmac_req)：STEP ‖ ID_B(32) ‖ UA(64) ‖ randomB(16)，桩挑战云
    std::string random_b = crypto.random_bytes_hex(16);
    std::vector<unsigned char> p1 = {frame::STEP_1_REQ};
    append(p1, id32(cfg.pile_id));
    append(p1, frame::hex_to_bytes(static_key.public_hex));
    append(p1, frame::hex_to_bytes(random_b));
    net.write_bytes(frame::encode(frame::TYPE_P1_UP, seq++, host, p1));

    // msg2 (0x3A/0x12 hmac_challenge)：STEP ‖ ID_A(32) ‖ mac_B(32) ‖ randomA(16)
    frame::Frame f = frame::read(net);
    frame::Reader r(f.payload);
    if (f.type != frame::TYPE_P1_DOWN || r.u8() != frame::STEP_1_RESP) {
        throw std::runtime_error("第一阶段: 云平台未返回挑战应答报文，中止");
    }
    r.take(32);  // ID_A（云编号，仅记录）
    std::string mac_b_hex = r.take_hex(32);
    std::string random_a_hex = r.take_hex(16);
    if (!crypto.hmac_sm3_verify(cfg.shared_key_hex, random_b, mac_b_hex)) {
        throw std::runtime_error("第一阶段: 云平台 MAC 校验失败，中止（对端可能不持有预共享密钥）");
    }
    LOG_INFO("第一阶段: 云平台身份校验通过（HMAC-SM3 over random_B）。");

    // msg3 (0x39/0x21 hmac_response)：STEP ‖ mac_A(32)，桩应答云的挑战
    std::vector<unsigned char> p3 = {frame::STEP_2_REQ};
    append(p3, frame::hex_to_bytes(crypto.hmac_sm3_hex(cfg.shared_key_hex, random_a_hex)));
    net.write_bytes(frame::encode(frame::TYPE_P1_UP, seq++, host, p3));

    // msg4 (0x3A/0x22 auth_result)：STEP ‖ result(1) ‖ ID_A(32)
    frame::Frame fa = frame::read(net);
    frame::Reader ra(fa.payload);
    if (fa.type != frame::TYPE_P1_DOWN || ra.u8() != frame::STEP_2_RESP) {
        throw std::runtime_error("第一阶段: 未收到认证结果报文，中止");
    }
    if (ra.u8() != frame::RESULT_OK) {
        throw std::runtime_error("第一阶段: 桩身份未通过云平台校验，中止");
    }
    LOG_INFO("第一阶段: 双向 HMAC 认证通过。");

    // msg5 (0x39/0x31 pk_request)：STEP ‖ ID_B(32) ‖ UA(64)
    std::vector<unsigned char> p5 = {frame::STEP_3_REQ};
    append(p5, id32(cfg.pile_id));
    append(p5, frame::hex_to_bytes(static_key.public_hex));
    net.write_bytes(frame::encode(frame::TYPE_P1_UP, seq++, host, p5));

    // msg6 (0x3A/0x32 pk_response)：STEP ‖ WA(64) ‖ partialPrivate(129) ‖ Ppub(64)
    frame::Frame fp = frame::read(net);
    frame::Reader rp(fp.payload);
    if (fp.type != frame::TYPE_P1_DOWN || rp.u8() != frame::STEP_3_RESP) {
        throw std::runtime_error("第一阶段: 未收到部分私钥下发报文，中止");
    }
    PileKeystore ks;
    ks.id = cfg.pile_id;
    ks.ua_secret_hex = static_key.secret_hex;
    ks.claimed_public_hex = rp.take_hex(64);
    std::string partial_hex = rp.take_hex(129);
    ks.master_public_hex = rp.take_hex(64);
    ks.full_private_hex = crypto.compose_full_private(static_key.secret_hex, partial_hex);
    ks.save(cfg.keystore_path);
    LOG_INFO("第一阶段完成: 已组合 dA 并持久化到 " + cfg.keystore_path);
}

// 第二阶段：SM2 签名的 ECDH 两步协商 + 双向回执，派生会话密钥（二进制帧）
void session(const PileConfig& cfg, CryptoUtils& crypto, const PileKeystore& ks) {
    NetClient net(cfg.connect_timeout_ms, cfg.read_timeout_ms);
    net.connect(cfg.cloud_host, cfg.cloud_port);
    auto host = frame::bcd7_from_id(cfg.pile_id);
    uint16_t seq = 1;

    // 桩（发起方 B）：自生成 nonce、UUID、临时密钥 (r_B, R_B)，签发起方 transcript
    std::string nonce = crypto.random_bytes_hex(16);
    std::string uuid = crypto.random_bytes_hex(16);  // 32 字节 ASCII 会话标识
    KeyMaterial eph = crypto.generate_static_key();  // (r_B, R_B)
    std::string sig = crypto.sign_initiator(
        eph.public_hex, ks.id, ks.claimed_public_hex, nonce, ks.full_private_hex);

    // msg1 (0x3B/0x11 ka_request)：STEP ‖ UUID(32) ‖ CP56(7) ‖ ID_B(32) ‖ WB(64) ‖ rB(64) ‖ nonce(16) ‖ sig_B(64)
    std::vector<unsigned char> p1 = {frame::STEP_1_REQ};
    append(p1, std::vector<unsigned char>(uuid.begin(), uuid.end()));
    append(p1, frame::cp56_now());
    append(p1, id32(ks.id));
    append(p1, frame::hex_to_bytes(ks.claimed_public_hex));
    append(p1, frame::hex_to_bytes(eph.public_hex));
    append(p1, frame::hex_to_bytes(nonce));
    append(p1, frame::hex_to_bytes(sig));
    net.write_bytes(frame::encode(frame::TYPE_P2_UP, seq++, host, p1));

    // msg2 (0x3C/0x12 ka_response)：STEP ‖ UUID(32) ‖ CP56(7) ‖ result(1) ‖ ID_A(32) ‖ WA(64) ‖ rA(64) ‖ sig_A(64)
    frame::Frame f = frame::read(net);
    frame::Reader r(f.payload);
    if (f.type != frame::TYPE_P2_DOWN || r.u8() != frame::STEP_1_RESP) {
        throw std::runtime_error("密钥协商失败，云平台未返回有效响应");
    }
    r.take(32);       // UUID 回填（会话关联，仅记录）
    r.take(7);        // CP56Time2a（传输元数据）
    if (r.u8() != frame::RESULT_OK) {
        throw std::runtime_error("密钥协商失败：云平台未通过桩端签名验签");
    }
    std::string cloud_id = id_from32(r.take(32));  // ID_A
    std::string cloud_claimed = r.take_hex(64);    // W_A
    std::string r_a = r.take_hex(64);              // R_A（云临时公钥）
    std::string cloud_sig = r.take_hex(64);        // sig_A
    // 用持久化的 Ppub 重构云平台完整公钥 PA_cloud = WA_cloud + λ·Ppub，验响应方签名
    std::string cloud_full_public = crypto.reconstruct_full_public(
        cloud_id, cloud_claimed, ks.master_public_hex);
    bool cloud_ok = crypto.verify_responder(
        r_a, eph.public_hex, cloud_id, cloud_claimed, nonce, cloud_sig, cloud_full_public);

    // msg3 (0x3B/0x21 ka_confirm)：STEP ‖ UUID(32) ‖ CP56(7) ‖ result(1) ‖ received(1)
    std::vector<unsigned char> p3 = {frame::STEP_2_REQ};
    append(p3, std::vector<unsigned char>(uuid.begin(), uuid.end()));
    append(p3, frame::cp56_now());
    p3.push_back(cloud_ok ? frame::RESULT_OK : frame::RESULT_FAIL);
    p3.push_back(frame::RECEIVED_YES);
    net.write_bytes(frame::encode(frame::TYPE_P2_UP, seq++, host, p3));
    if (!cloud_ok) {
        throw std::runtime_error("云平台签名校验失败");
    }
    LOG_INFO("第二阶段: 云平台签名校验通过（已回执）。");

    // SK = SM3(Sx ‖ R_A ‖ R_B ‖ ID_A ‖ ID_B ‖ nonce)
    std::string session_key = crypto.derive_session_key(
        eph.secret_hex, r_a, r_a, eph.public_hex, cloud_id, ks.id, nonce);
    if (session_key.size() != 64) {
        throw std::runtime_error("会话密钥派生异常");
    }

    // msg4 (0x3C/0x22 ka_ack)：STEP ‖ UUID(32) ‖ CP56(7) ‖ received(1)，云确认收到桩回执
    frame::Frame fk = frame::read(net);
    frame::Reader rk(fk.payload);
    if (fk.type != frame::TYPE_P2_DOWN || rk.u8() != frame::STEP_2_RESP) {
        throw std::runtime_error("第二阶段: 未收到云平台回执确认");
    }
    rk.take(32);  // UUID
    rk.take(7);   // CP56
    bool acked = rk.u8() == frame::RECEIVED_YES;

    std::string fingerprint = crypto.sm3_hex_of_ascii(session_key).substr(0, 16);
    LOG_INFO(std::string("第二阶段: 会话密钥协商完成（指纹 SM3(SK)[0:16]=") + fingerprint +
             "，云回执=" + (acked ? "已确认" : "未确认") + "，密钥不落日志）。");
}

}  // namespace

int main(int argc, char** argv) {
    try {
        std::string config_path = (argc > 1) ? argv[1] : "config/pile.conf";
        PileConfig cfg = PileConfig::load(config_path);
        CryptoUtils crypto;

        if (!PileKeystore::exists(cfg.keystore_path)) {
            LOG_INFO("未发现本地密钥，执行第一阶段申请。");
            provision(cfg, crypto);
        } else {
            LOG_INFO("已存在本地密钥（" + cfg.keystore_path + "），跳过第一阶段。");
        }

        PileKeystore ks = PileKeystore::load(cfg.keystore_path);
        session(cfg, crypto, ks);
        return 0;
    } catch (const std::exception& e) {
        LOG_ERROR(std::string("充电桩运行异常: ") + e.what());
        return 1;
    }
}
