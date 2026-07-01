#include <nlohmann/json.hpp>

#include <exception>
#include <string>

#include "config.h"
#include "crypto_utils.h"
#include "logging.h"
#include "net_client.h"

// ============================================================================
// CL-PKC 充电桩客户端（国密 SM2，隐式证书方案）。
//
// TCP 长连接完成：① HMAC-SM3 挑战-响应认证 → ② 经云平台向 KGC 申请部分私钥（声明公钥 WA
// + SM2 加密的 tA）→ 组合完整私钥 dA=tA+ua → ③ 带 SM2 签名的 ECDH 协商 → ④ 会话密钥派生。
// 防重放仅用握手 nonce（无时间戳）。
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

std::string field(const json& j, const char* key) {
    if (!j.contains(key) || !j[key].is_string()) {
        throw std::runtime_error(std::string("报文缺少字段: ") + key);
    }
    return j[key].get<std::string>();
}

}  // namespace

int main(int argc, char** argv) {
    try {
        std::string config_path = (argc > 1) ? argv[1] : "config/pile.conf";
        PileConfig cfg = PileConfig::load(config_path);

        CryptoUtils crypto;
        KeyMaterial static_key = crypto.generate_static_key();  // (ua, UA)
        LOG_INFO("启动充电桩，本地公钥 UA = " + static_key.public_hex);

        NetClient net(cfg.connect_timeout_ms, cfg.read_timeout_ms);
        net.connect(cfg.cloud_host, cfg.cloud_port);
        LOG_INFO("已连接云平台 " + cfg.cloud_host + ":" + std::to_string(cfg.cloud_port));

        // ① 挑战-响应（HMAC-SM3）
        json challenge = read_msg(net);
        std::string nonce = field(challenge, "nonce");
        send_msg(net, json{
            {"type", "hmac"},
            {"id", cfg.pile_id},
            {"publicKey", static_key.public_hex},
            {"mac", crypto.hmac_sm3_hex(cfg.shared_key_hex, nonce)}
        });

        json auth = read_msg(net);
        if (field(auth, "type") != "auth_ok") {
            LOG_ERROR("HMAC 认证失败，终止。");
            return 1;
        }
        std::string cloud_id = field(auth, "id");
        std::string cloud_claimed_public = field(auth, "claimedPublic");  // WA_cloud
        LOG_INFO("HMAC 认证通过。");

        // ② 申请部分私钥（经云平台透传 KGC）
        send_msg(net, json{
            {"type", "partial_key_request"},
            {"id", cfg.pile_id},
            {"publicKey", static_key.public_hex}
        });
        json partial = read_msg(net);
        std::string wa_pile = field(partial, "claimedPublic");       // WA_pile
        std::string master_public = field(partial, "masterPublicKey"); // Ppub
        std::string full_private = crypto.compose_full_private(static_key.secret_hex, field(partial, "partialPrivate"));
        LOG_INFO("已组合完整私钥 dA=tA+ua，声明公钥 WA = " + wa_pile);

        // ③ 发起带 SM2 签名的 KA（transcript 绑 nonce；wb 用云平台声明公钥）
        KeyMaterial eph = crypto.generate_static_key();  // (a, RA)
        std::string sig = crypto.sign_transcript(eph.public_hex, cfg.pile_id, cloud_claimed_public, nonce, full_private);
        send_msg(net, json{
            {"type", "ka_request"},
            {"id", cfg.pile_id},
            {"claimedPublic", wa_pile},
            {"ra", eph.public_hex},
            {"sig", sig}
        });

        // ④ 校验云平台响应并派生会话密钥
        json ka = read_msg(net);
        if (field(ka, "type") != "ka_response") {
            LOG_ERROR("密钥协商失败，云平台未返回有效响应。");
            return 1;
        }
        std::string rb = field(ka, "rb");
        // 用云平台声明公钥重构其完整公钥 PA_cloud = WA_cloud + λ·Ppub
        std::string cloud_full_public = crypto.reconstruct_full_public(
            field(ka, "id"), field(ka, "claimedPublic"), master_public);
        if (!crypto.verify_transcript(rb, field(ka, "id"), eph.public_hex, nonce, field(ka, "sig"), cloud_full_public)) {
            LOG_ERROR("云平台签名校验失败，拒绝本次协商。");
            return 1;
        }
        LOG_INFO("云平台签名校验通过。");

        std::string session_key = crypto.derive_session_key(
            eph.secret_hex, rb, eph.public_hex, rb, cfg.pile_id, field(ka, "id"), nonce);
        if (session_key.size() != 64) {
            LOG_ERROR("会话密钥派生异常。");
            return 1;
        }
        std::string fingerprint = crypto.sm3_hex_of_ascii(session_key).substr(0, 16);
        LOG_INFO("会话密钥协商完成（指纹 SM3(SK)[0:16]=" + fingerprint + "，密钥不落日志）。");
        return 0;
    } catch (const std::exception& e) {
        LOG_ERROR(std::string("充电桩运行异常: ") + e.what());
        return 1;
    }
}
