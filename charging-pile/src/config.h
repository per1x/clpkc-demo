#pragma once

#include <string>

// ============================================================================
// 充电桩配置。优先级：环境变量 > 配置文件 > 默认值。
// 生产化要点（P2-14）：不再硬编码服务器地址/预共享密钥，改为外置配置。
// ============================================================================

struct PileConfig {
    std::string pile_id = "pile-001";
    std::string cloud_host = "127.0.0.1";
    int cloud_port = 9000;
    // 与云平台的全局预共享密钥（HMAC），64 字符 hex
    std::string shared_key_hex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    int connect_timeout_ms = 3000;
    int read_timeout_ms = 15000;

    // 从配置文件（key=value，# 注释）加载，随后用环境变量覆盖。
    // 找不到文件时仅使用默认值 + 环境变量，不视为错误。
    static PileConfig load(const std::string& path);
};
