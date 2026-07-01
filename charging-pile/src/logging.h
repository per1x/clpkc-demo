#pragma once

#include <cstdio>
#include <ctime>
#include <mutex>
#include <string>

// ============================================================================
// 轻量级分级日志（输出到 stderr）。生产化要点：带时间戳与级别，
// 调用方负责不将私钥/会话密钥等敏感值传入日志。
// ============================================================================

namespace clpkc_log {

enum class Level { INFO, WARN, ERROR };

inline std::mutex& mutex() {
    static std::mutex m;
    return m;
}

inline const char* level_name(Level l) {
    switch (l) {
        case Level::INFO: return "INFO";
        case Level::WARN: return "WARN";
        case Level::ERROR: return "ERROR";
    }
    return "INFO";
}

inline void log(Level level, const std::string& msg) {
    std::time_t t = std::time(nullptr);
    std::tm tm{};
    localtime_r(&t, &tm);
    char ts[24];
    std::strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tm);
    std::lock_guard<std::mutex> guard(mutex());
    std::fprintf(stderr, "%s [%s] [Pile] %s\n", ts, level_name(level), msg.c_str());
    std::fflush(stderr);
}

}  // namespace clpkc_log

#define LOG_INFO(msg) ::clpkc_log::log(::clpkc_log::Level::INFO, (msg))
#define LOG_WARN(msg) ::clpkc_log::log(::clpkc_log::Level::WARN, (msg))
#define LOG_ERROR(msg) ::clpkc_log::log(::clpkc_log::Level::ERROR, (msg))
