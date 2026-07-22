#include <nlohmann/json.hpp>

#include <exception>
#include <string>

#include "clpkc_sdk.h"
#include "config.h"
#include "keystore.h"
#include "logging.h"
#include "net_client.h"

// ============================================================================
// CL-PKC 充电桩客户端（国密 SM2，隐式证书方案，两阶段）。
//
// 第一阶段(provision，仅首次)：双向 HMAC-SM3 挑战应答（桩出 random_B、云出 random_A，
//   双方互验 MAC，任一侧失败即中止）→ 经云平台向 KGC 申请部分私钥 →
//   组合完整私钥 dA=tA+ua → 本地持久化。
// 第二阶段(session，每次)：加载本地密钥 → 直接带 SM2 签名的 ECDH 协商 → 会话密钥派生。
//   本阶段不涉及 HMAC 认证与 KGC 申请。
// nonce 由桩自生成（16 字节 CSPRNG，会话新鲜随机数，绑定签名防重放），随首报文发给云；云不下发 challenge。
// ============================================================================

using json = nlohmann::json;

namespace {

json read_msg(NetClient& net) {
    std::string line = net.read_line();
    json j = json::parse(line, nullptr, /*allow_exceptions=*/false);
    if (j.is_discarded() || !j.is_object()) {
        throw std::runtime_error("收到非法 JSON 报文");
    }
    return j;
}

void send_msg(NetClient& net, const json& j) {
    net.write_line(j.dump());
}

// hex → 原始字节（非密码学工具；SDK 未提供，仅用于把 SK 解码后算日志指纹）
std::string hex_to_raw(const std::string& hex) {
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        throw std::runtime_error("非法 hex 字符");
    };
    if (hex.size() % 2 != 0) {
        throw std::runtime_error("hex 长度必须为偶数");
    }
    std::string out;
    out.reserve(hex.size() / 2);
    for (std::size_t i = 0; i < hex.size(); i += 2) {
        out.push_back(static_cast<char>((nib(hex[i]) << 4) | nib(hex[i + 1])));
    }
    return out;
}

std::string field(const json& j, const char* key) {
    if (!j.contains(key) || !j[key].is_string()) {
        throw std::runtime_error(std::string("报文缺少字段: ") + key);
    }
    return j[key].get<std::string>();
}

// 第一阶段：申请无证书密钥对并落地
void provision(const PileConfig& cfg) {
    // ID_B = 7 字节 BCD 主机编号 ‖ 25 字节 0x00；线上一律传 64 字符 hex
    const std::string id_hex = clpkc::make_id_from_bcd(cfg.host_no);
    LOG_INFO("第一阶段: 主机编号 " + cfg.host_no + " → ID_B(32B hex) = " + id_hex);
    clpkc::KeyMaterial static_key = clpkc::generate_static_key();  // (ua, UA)
    LOG_INFO("第一阶段: 本地公钥 UA = " + static_key.public_hex);

    NetClient net(cfg.connect_timeout_ms, cfg.read_timeout_ms);
    net.connect(cfg.cloud_host, cfg.cloud_port);

    // 第一阶段双向挑战应答 msg1：桩生成 random_B（16 字节）挑战云平台
    std::string random_b = clpkc::random_bytes_hex(16);
    send_msg(net, json{
        {"type", "hmac"},
        {"id", id_hex},
        {"publicKey", static_key.public_hex},
        {"randomB", random_b}
    });

    // msg2：云回 HMAC(PSK, random_B) 自证身份 + 自己的挑战 random_A。桩必须验云的 MAC。
    json challenge = read_msg(net);
    if (field(challenge, "type") != "hmac_challenge") {
        throw std::runtime_error("第一阶段: 云平台未返回挑战应答报文，中止");
    }
    if (!clpkc::hmac_sm3_verify(cfg.shared_key_hex, random_b, field(challenge, "mac"))) {
        throw std::runtime_error("第一阶段: 云平台 MAC 校验失败，中止（对端可能不持有预共享密钥）");
    }
    LOG_INFO("第一阶段: 云平台身份校验通过（HMAC-SM3 over random_B）。");

    // msg3：桩用 PSK 应答云的挑战 random_A
    send_msg(net, json{
        {"type", "hmac_response"},
        {"id", id_hex},
        {"mac", clpkc::hmac_sm3_hex(cfg.shared_key_hex, field(challenge, "randomA"))}
    });

    // msg4：云验桩通过才放行
    json auth = read_msg(net);
    if (field(auth, "type") != "auth_ok") {
        throw std::runtime_error("第一阶段: 桩身份未通过云平台校验，中止");
    }
    LOG_INFO("第一阶段: 双向 HMAC 认证通过。");
    send_msg(net, json{
        {"type", "partial_key_request"},
        {"id", id_hex},
        {"publicKey", static_key.public_hex}
    });
    json partial = read_msg(net);
    PileKeystore ks;
    ks.id = id_hex;
    ks.ua_secret_hex = static_key.secret_hex;
    ks.claimed_public_hex = field(partial, "claimedPublic");
    ks.master_public_hex = field(partial, "masterPublicKey");
    ks.full_private_hex = clpkc::compose_full_private(static_key.secret_hex, field(partial, "partialPrivate"));
    ks.save(cfg.keystore_path);
    LOG_INFO("第一阶段完成: 已组合 dA 并持久化到 " + cfg.keystore_path);
}

// 第二阶段：用本地密钥协商会话密钥
void session(const PileConfig& cfg, const PileKeystore& ks) {
    NetClient net(cfg.connect_timeout_ms, cfg.read_timeout_ms);
    net.connect(cfg.cloud_host, cfg.cloud_port);

    // 桩（发起方 B）：自生成 nonce 与临时密钥 (r_B, R_B)，直接发 ka_request（msg1）
    std::string nonce = clpkc::random_bytes_hex(16);
    clpkc::KeyMaterial eph = clpkc::generate_static_key();  // (r_B, R_B)
    // 桩签（发起方）transcript = R_B ‖ ID_B ‖ W_B ‖ nonce
    std::string sig = clpkc::sign_initiator(
        eph.public_hex, ks.id, ks.claimed_public_hex, nonce, ks.full_private_hex);
    send_msg(net, json{
        {"type", "ka_request"},
        {"id", ks.id},
        {"claimedPublic", ks.claimed_public_hex},
        {"rB", eph.public_hex},
        {"nonce", nonce},
        {"sig", sig}
    });

    json ka = read_msg(net);  // msg2
    if (field(ka, "type") != "ka_response") {
        throw std::runtime_error("密钥协商失败，云平台未返回有效响应");
    }
    // 用持久化的 Ppub 重构云平台完整公钥 PA_cloud = WA_cloud + λ·Ppub
    std::string cloud_id = field(ka, "id");                   // ID_A
    std::string cloud_claimed = field(ka, "claimedPublic");  // W_A
    std::string r_a = field(ka, "rA");                       // R_A（云临时公钥）
    std::string cloud_full_public = clpkc::reconstruct_full_public(
        cloud_id, cloud_claimed, ks.master_public_hex);
    // 验云签（响应方）transcript = R_A ‖ R_B ‖ ID_A ‖ W_A ‖ nonce
    if (!clpkc::verify_responder(
            r_a, eph.public_hex, cloud_id, cloud_claimed, nonce, field(ka, "sig"), cloud_full_public)) {
        throw std::runtime_error("云平台签名校验失败");
    }
    LOG_INFO("第二阶段: 云平台签名校验通过。");

    // SK = SM3(Sx ‖ R_A ‖ R_B ‖ ID_A ‖ ID_B ‖ nonce)
    std::string session_key = clpkc::derive_session_key(
        eph.secret_hex, r_a, r_a, eph.public_hex, cloud_id, ks.id, nonce);
    if (session_key.size() != 64) {
        throw std::runtime_error("会话密钥派生异常");
    }
    std::string fingerprint = clpkc::sm3_hex_of_ascii(hex_to_raw(session_key)).substr(0, 16);
    LOG_INFO("第二阶段: 会话密钥协商完成（指纹 SM3(SK)[0:16]=" + fingerprint + "，密钥不落日志）。");
}

}  // namespace

int main(int argc, char** argv) {
    try {
        std::string config_path = (argc > 1) ? argv[1] : "config/pile.conf";
        PileConfig cfg = PileConfig::load(config_path);

        if (!PileKeystore::exists(cfg.keystore_path)) {
            LOG_INFO("未发现本地密钥，执行第一阶段申请。");
            provision(cfg);
        } else {
            LOG_INFO("已存在本地密钥（" + cfg.keystore_path + "），跳过第一阶段。");
        }

        PileKeystore ks = PileKeystore::load(cfg.keystore_path);
        session(cfg, ks);
        return 0;
    } catch (const std::exception& e) {
        LOG_ERROR(std::string("充电桩运行异常: ") + e.what());
        return 1;
    }
}
