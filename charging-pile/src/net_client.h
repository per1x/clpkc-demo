#pragma once

#include <cstddef>
#include <map>
#include <string>

// ============================================================================
// TCP 长连接客户端（生产化替换原逐字节 read 的简化实现）。
//
// 改进点：非阻塞 connect + 超时；带超时的行读取；单行长度上限（防内存耗尽）；
// 缓冲读取（一次 recv 多字节，内部缓存按行切分）。连接建立后保持长连接。
// ============================================================================

class NetClient {
public:
    NetClient(int connect_timeout_ms, int read_timeout_ms);
    ~NetClient();

    NetClient(const NetClient&) = delete;
    NetClient& operator=(const NetClient&) = delete;

    // 连接失败抛 std::runtime_error。
    void connect(const std::string& host, int port);

    // 发送一行（追加 '\n'）。失败抛异常。
    void write_line(const std::string& line);

    // 读取一行（不含 '\n'）。超时/关闭/超长抛 std::runtime_error。
    std::string read_line();

    void close();

private:
    int fd_ = -1;
    int connect_timeout_ms_;
    int read_timeout_ms_;
    std::string buffer_;  // 已接收但尚未按行消费的数据
    static constexpr std::size_t kMaxLineBytes = 16 * 1024;
};
