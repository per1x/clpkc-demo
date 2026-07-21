#include "net_client.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <stdexcept>

namespace {
void set_blocking(int fd, bool blocking) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (blocking) {
        fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
    } else {
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }
}
}  // namespace

NetClient::NetClient(int connect_timeout_ms, int read_timeout_ms)
    : connect_timeout_ms_(connect_timeout_ms), read_timeout_ms_(read_timeout_ms) {}

NetClient::~NetClient() {
    close();
}

void NetClient::connect(const std::string& host, int port) {
    struct addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* res = nullptr;
    std::string port_str = std::to_string(port);
    if (getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res) != 0 || !res) {
        throw std::runtime_error("DNS/地址解析失败: " + host);
    }

    int fd = -1;
    for (struct addrinfo* rp = res; rp; rp = rp->ai_next) {
        fd = ::socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) {
            continue;
        }
        set_blocking(fd, false);
        int rc = ::connect(fd, rp->ai_addr, rp->ai_addrlen);
        if (rc == 0) {
            break;  // 立即连接成功
        }
        if (errno == EINPROGRESS) {
            fd_set wset;
            FD_ZERO(&wset);
            FD_SET(fd, &wset);
            struct timeval tv{};
            tv.tv_sec = connect_timeout_ms_ / 1000;
            tv.tv_usec = (connect_timeout_ms_ % 1000) * 1000;
            if (::select(fd + 1, nullptr, &wset, nullptr, &tv) > 0) {
                int err = 0;
                socklen_t len = sizeof(err);
                getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len);
                if (err == 0) {
                    break;  // 连接成功
                }
            }
        }
        ::close(fd);
        fd = -1;
    }
    freeaddrinfo(res);

    if (fd < 0) {
        throw std::runtime_error("连接云平台失败: " + host + ":" + std::to_string(port));
    }
    set_blocking(fd, true);
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    // 读超时
    struct timeval rtv{};
    rtv.tv_sec = read_timeout_ms_ / 1000;
    rtv.tv_usec = (read_timeout_ms_ % 1000) * 1000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &rtv, sizeof(rtv));
    fd_ = fd;
}

void NetClient::write_line(const std::string& line) {
    std::string data = line + "\n";
    std::size_t sent = 0;
    while (sent < data.size()) {
        ssize_t n = ::send(fd_, data.data() + sent, data.size() - sent, 0);
        if (n <= 0) {
            throw std::runtime_error("发送失败: " + std::string(std::strerror(errno)));
        }
        sent += static_cast<std::size_t>(n);
    }
}

std::string NetClient::read_line() {
    while (true) {
        auto pos = buffer_.find('\n');
        if (pos != std::string::npos) {
            std::string line = buffer_.substr(0, pos);
            buffer_.erase(0, pos + 1);
            if (!line.empty() && line.back() == '\r') {
                line.pop_back();
            }
            return line;
        }
        if (buffer_.size() > kMaxLineBytes) {
            throw std::runtime_error("单行超过最大长度上限");
        }
        char chunk[4096];
        ssize_t n = ::recv(fd_, chunk, sizeof(chunk), 0);
        if (n == 0) {
            throw std::runtime_error("连接被对端关闭");
        }
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                throw std::runtime_error("读超时");
            }
            throw std::runtime_error("接收失败: " + std::string(std::strerror(errno)));
        }
        buffer_.append(chunk, static_cast<std::size_t>(n));
    }
}

void NetClient::close() {
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
}
