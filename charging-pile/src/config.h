#pragma once

#include <string>

// ============================================================================
// 充电桩配置。优先级：环境变量 > 配置文件 > 默认值。
// 服务器地址、预共享密钥等均为外置配置，不在源码中硬编码。
// ============================================================================

struct PileConfig {
    // 主机编号：≤14 位十进制数字串。BCD 编码成 7 字节后构成 ID_B 的前 7 字节。
    // 不足 14 位时**左侧补 '0'**（保持数值不变），详见 README。
    std::string host_no = "00000000000001";
    std::string cloud_host = "127.0.0.1";
    int cloud_port = 9000;
    // 与云平台的全局预共享密钥（HMAC），16 字节 SM4 密钥，32 字符 hex
    std::string shared_key_hex = "00112233445566778899aabbccddeeff";
    int connect_timeout_ms = 3000;
    int read_timeout_ms = 15000;
    // 本地密钥持久化文件：存在则跳过第一阶段直接协商会话密钥
    std::string keystore_path = "pile-keystore.json";

    // 从配置文件（key=value，# 注释）加载，随后用环境变量覆盖。
    // 找不到文件时仅使用默认值 + 环境变量，不视为错误。
    static PileConfig load(const std::string& path);
};
