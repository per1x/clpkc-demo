#include "crypto_utils.h"
#include "json_line.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <ctime>
#include <iostream>
#include <map>
#include <sstream>
#include <stdexcept>

namespace {
std::string read_line(int fd) {
    std::string out;
    char ch;
    while (true) {
        ssize_t n = ::read(fd, &ch, 1);
        if (n <= 0) {
            throw std::runtime_error("套接字连接已关闭");
        }
        if (ch == '\n') {
            return out;
        }
        out.push_back(ch);
    }
}

void write_line(int fd, const std::map<std::string, std::string>& kv) {
    std::string line = json_stringify(kv) + "\n";
    ::write(fd, line.data(), line.size());
    std::cout << "[Pile][Socket] 发送报文: " << json_stringify(kv) << "\n";
}

std::string now_iso8601() {
    std::time_t t = std::time(nullptr);
    std::tm tm = *std::gmtime(&t);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
    return buf;
}
}

int main() {
    const std::string pile_id = "pile-001";
    const std::string host = "127.0.0.1";
    const int port = 9000;
    const std::string shared_key = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    CryptoUtils crypto;
    KeyMaterial static_key = crypto.generate_static_key();
    std::cout << "[Pile] 启动充电桩 Demo，静态公钥 P_i = " << static_key.public_hex << "\n";

    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, host.c_str(), &addr.sin_addr);
    if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        std::perror("连接 Cloud 失败");
        return 1;
    }
    std::cout << "[Pile] 已连接到 Cloud TCP 服务: " << host << ":" << port << "\n";

    // 第一步：接收 Cloud 发来的挑战随机数，并回送 HMAC 证明自己持有预共享密钥。
    auto challenge = json_parse(read_line(fd));
    std::cout << "[Pile][Socket] 收到挑战报文: " << json_stringify(challenge) << "\n";
    std::string nonce = challenge["nonce"];
    write_line(fd, {
        {"type", "hmac"},
        {"id", pile_id},
        {"publicKey", static_key.public_hex},
        {"mac", crypto.hmac_sha256_hex(shared_key, nonce)}
    });

    auto auth = json_parse(read_line(fd));
    std::cout << "[Pile][Socket] 收到认证结果: " << json_stringify(auth) << "\n";
    if (auth["type"] != "auth_ok") {
        std::cerr << "[Pile] HMAC 认证失败，终止流程。\n";
        return 1;
    }
    const std::string cloud_static_public = auth["publicKey"];
    std::cout << "[Pile] HMAC 认证通过，Cloud 静态公钥 = " << cloud_static_public << "\n";

    // 第二步：通过 Cloud 透传向 KGC 申请部分私钥 d_i。
    write_line(fd, {
        {"type", "partial_key_request"},
        {"id", pile_id},
        {"publicKey", static_key.public_hex}
    });

    auto partial = json_parse(read_line(fd));
    std::cout << "[Pile][Socket] 收到部分私钥响应: " << json_stringify(partial) << "\n";
    const std::string decrypted_partial = crypto.ecies_decrypt(partial["partialPrivate"], static_key.secret_hex);
    const std::string full_private = crypto.compose_full_private(static_key.secret_hex, decrypted_partial);
    const std::string master_public = partial["masterPublicKey"];
    std::cout << "[Pile] 已 ECIES 解密部分私钥并根据 x_i + d_i 组装完整私钥 sk_i。\n";

    // 第三步：生成临时 ECDH 公钥 RA，并对 RA || IDA || WB || T 做签名。
    KeyMaterial eph = crypto.generate_static_key();
    std::string ta = now_iso8601();
    Signature sig = crypto.sign_transcript(eph.public_hex, pile_id, cloud_static_public, ta, full_private);
    std::cout << "[Pile] 生成临时公钥 RA = " << eph.public_hex << "\n";
    std::cout << "[Pile] 对协商报文进行签名，准备发起带认证的 ECDH。\n";
    write_line(fd, {
        {"type", "ka_request"},
        {"id", pile_id},
        {"publicKey", static_key.public_hex},
        {"ra", eph.public_hex},
        {"t", ta},
        {"sig", sig.to_hex()}
    });

    auto ka = json_parse(read_line(fd));
    std::cout << "[Pile][Socket] 收到协商响应: " << json_stringify(ka) << "\n";
    if (ka["type"] != "ka_response") {
        std::cerr << "[Pile] 密钥协商失败，Cloud 未返回有效响应。\n";
        return 1;
    }

    // 第四步：根据 Cloud 的静态公钥和 KGC 主公钥恢复 Cloud 完整公钥，再验签。
    const std::string cloud_full_public = crypto.derive_full_public(ka["id"], ka["publicKey"], master_public);
    const bool ok = crypto.verify_transcript(ka["rb"], ka["id"], eph.public_hex, ka["t"], ka["sig"], cloud_full_public);
    if (!ok) {
        std::cerr << "[Pile] Cloud 签名校验失败，拒绝使用本次协商结果。\n";
        return 1;
    }
    std::cout << "[Pile] Cloud 签名校验通过。\n";

    // 第五步：使用本地临时私钥和 Cloud 临时公钥 RB 计算最终会话密钥。
    const std::string session_key = crypto.derive_session_key(eph.secret_hex, ka["rb"], eph.public_hex, ka["rb"], pile_id, ka["id"], ta, ka["t"]);
    std::cout << "[Pile] 会话密钥协商完成，会话密钥 = " << session_key << "\n";
    ::close(fd);
    return 0;
}
