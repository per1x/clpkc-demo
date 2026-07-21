#include "config.h"

#include <cstdlib>
#include <fstream>
#include <sstream>
#include <string>

#include "logging.h"

namespace {

std::string trim(const std::string& s) {
    const char* ws = " \t\r\n";
    auto b = s.find_first_not_of(ws);
    if (b == std::string::npos) {
        return "";
    }
    auto e = s.find_last_not_of(ws);
    return s.substr(b, e - b + 1);
}

std::string env_or(const char* name, const std::string& fallback) {
    const char* v = std::getenv(name);
    return (v && *v) ? std::string(v) : fallback;
}

}  // namespace

PileConfig PileConfig::load(const std::string& path) {
    PileConfig cfg;

    std::ifstream in(path);
    if (in) {
        std::string line;
        while (std::getline(in, line)) {
            std::string s = trim(line);
            if (s.empty() || s[0] == '#') {
                continue;
            }
            auto eq = s.find('=');
            if (eq == std::string::npos) {
                continue;
            }
            std::string key = trim(s.substr(0, eq));
            std::string val = trim(s.substr(eq + 1));
            if (key == "pile.host_no") {
                cfg.host_no = val;
            } else if (key == "cloud.host") {
                cfg.cloud_host = val;
            } else if (key == "cloud.port") {
                cfg.cloud_port = std::stoi(val);
            } else if (key == "shared.key.hex") {
                cfg.shared_key_hex = val;
            } else if (key == "connect.timeout.ms") {
                cfg.connect_timeout_ms = std::stoi(val);
            } else if (key == "read.timeout.ms") {
                cfg.read_timeout_ms = std::stoi(val);
            } else if (key == "keystore.path") {
                cfg.keystore_path = val;
            }
        }
        LOG_INFO("已加载配置文件: " + path);
    } else {
        LOG_WARN("未找到配置文件 " + path + "，使用默认值 + 环境变量。");
    }

    // 环境变量覆盖
    cfg.host_no = env_or("CLPKC_PILE_HOST_NO", cfg.host_no);
    cfg.cloud_host = env_or("CLPKC_CLOUD_HOST", cfg.cloud_host);
    cfg.cloud_port = std::stoi(env_or("CLPKC_CLOUD_PORT", std::to_string(cfg.cloud_port)));
    cfg.shared_key_hex = env_or("CLPKC_SHARED_KEY_HEX", cfg.shared_key_hex);
    cfg.connect_timeout_ms =
        std::stoi(env_or("CLPKC_CONNECT_TIMEOUT_MS", std::to_string(cfg.connect_timeout_ms)));
    cfg.read_timeout_ms =
        std::stoi(env_or("CLPKC_READ_TIMEOUT_MS", std::to_string(cfg.read_timeout_ms)));
    cfg.keystore_path = env_or("CLPKC_KEYSTORE_PATH", cfg.keystore_path);
    return cfg;
}
