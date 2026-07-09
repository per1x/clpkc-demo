#include "keystore.h"

#include <nlohmann/json.hpp>

#include <sys/stat.h>

#include <fstream>
#include <stdexcept>

using json = nlohmann::json;

bool PileKeystore::exists(const std::string& path) {
    std::ifstream f(path);
    return f.good();
}

PileKeystore PileKeystore::load(const std::string& path) {
    std::ifstream f(path);
    if (!f) {
        throw std::runtime_error("无法打开密钥文件: " + path);
    }
    json j = json::parse(f, nullptr, /*allow_exceptions=*/false);
    if (j.is_discarded() || !j.is_object()) {
        throw std::runtime_error("密钥文件格式非法: " + path);
    }
    PileKeystore ks;
    ks.id = j.value("id", "");
    ks.ua_secret_hex = j.value("uaSecret", "");
    ks.full_private_hex = j.value("fullPrivate", "");
    ks.claimed_public_hex = j.value("claimedPublic", "");
    ks.master_public_hex = j.value("masterPublic", "");
    if (ks.id.empty() || ks.full_private_hex.empty() || ks.claimed_public_hex.empty()
        || ks.master_public_hex.empty()) {
        throw std::runtime_error("密钥文件字段缺失: " + path);
    }
    return ks;
}

void PileKeystore::save(const std::string& path) const {
    json j = {
        {"id", id},
        {"uaSecret", ua_secret_hex},
        {"fullPrivate", full_private_hex},
        {"claimedPublic", claimed_public_hex},
        {"masterPublic", master_public_hex}
    };
    std::ofstream f(path, std::ios::trunc);
    if (!f) {
        throw std::runtime_error("无法写入密钥文件: " + path);
    }
    f << j.dump(2);
    f.close();
    ::chmod(path.c_str(), S_IRUSR | S_IWUSR);  // 0600
}
