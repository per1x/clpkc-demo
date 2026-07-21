#pragma once

#include <string>

// ============================================================================
// 桩本地密钥持久化。第一阶段(provision)申请到密钥后落地；之后每次会话直接加载使用，
// 此后各次会话直接用本地密钥协商，不向 KGC 申请、不走 HMAC 认证。
//
// 安全说明：明文 JSON 仅为落地方便，文件权限限制为 0600；生产环境建议使用安全存储/加密。
// ============================================================================

struct PileKeystore {
    std::string id;                  // 桩编号
    std::string ua_secret_hex;       // 本地私钥 ua
    std::string full_private_hex;    // 完整私钥 dA = tA + ua
    std::string claimed_public_hex;  // 声明公钥 WA
    std::string master_public_hex;   // KGC 主公钥 Ppub

    static bool exists(const std::string& path);
    // 加载失败抛 std::runtime_error
    static PileKeystore load(const std::string& path);
    // 保存并将权限设为 0600
    void save(const std::string& path) const;
};
