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

// ============================================================================
// @file main.cpp
// @brief CL-PKC 充电桩客户端主程序
//
// 本文件实现了充电桩（客户端）与 Cloud 服务器之间的完整密钥协商流程：
// 1. 预共享密钥 HMAC 身份认证
// 2. 向 KGC 申请部分私钥（通过 Cloud 透传）
// 3. 带签名的 ECDH 密钥协商
// 4. 会话密钥派生
//
// 协议基于 CL-PKC（无证书公钥密码体系），所有通信通过 TCP 套接字
// 以 JSON 行协议（每行一个 JSON 对象，以换行符分隔）进行。
// ============================================================================

namespace {

// ---------------------------------------------------------------------------
/// @brief 从套接字文件描述符中逐字符读取一行（以 '\n' 结尾）
///
/// 每次调用 read() 读取一个字符，直到遇到换行符或连接关闭。
///
/// @param fd 已连接的 TCP 套接字文件描述符
/// @return 不含换行符的行内容字符串
/// @throws std::runtime_error 若 read() 返回 <= 0（连接关闭或错误）
///
/// @warning 此实现为演示用途的简化实现，逐字符读取效率较低。
///          生产环境中应考虑缓冲 I/O 或使用成熟的网络库。
// ---------------------------------------------------------------------------
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

// ---------------------------------------------------------------------------
/// @brief 将键值对映射序列化为 JSON 字符串，并通过套接字发送一行
///
/// 发送格式：JSON字符串 + "\n"
/// 同时在控制台打印发送内容，便于调试和协议追踪。
///
/// @param fd TCP 套接字文件描述符
/// @param kv 要发送的键值对映射（使用 json_stringify 序列化为 JSON）
// ---------------------------------------------------------------------------
void write_line(int fd, const std::map<std::string, std::string>& kv) {
    std::string line = json_stringify(kv) + "\n";
    ::write(fd, line.data(), line.size());
    std::cout << "[Pile][Socket] 发送报文: " << json_stringify(kv) << "\n";
}

// ---------------------------------------------------------------------------
/// @brief 获取当前 UTC 时间的 ISO-8601 格式字符串
///
/// 格式：YYYY-MM-DDTHH:MM:SSZ（例如 "2025-05-19T12:30:45Z"）
///
/// @return ISO-8601 UTC 时间字符串
///
/// @note 此时间戳用于密钥协商 transcript 中的重放攻击防护。
///       时间戳将绑定到 Schnorr 签名中，即使攻击者重放旧消息，
///       签名验证也会因时间戳不匹配而失败。
// ---------------------------------------------------------------------------
std::string now_iso8601() {
    std::time_t t = std::time(nullptr);
    std::tm tm = *std::gmtime(&t);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
    return buf;
}
}

// ============================================================================
// 主函数：充电桩密钥协商完整流程
// ============================================================================
int main() {
    // ---- 配置参数 ----
    const std::string pile_id = "pile-001";     // 充电桩身份标识（CL-PKC 中的 ID）
    const std::string host = "127.0.0.1";        // Cloud 服务器 IP
    const int port = 9000;                       // Cloud 服务器端口
    // 预共享密钥：充电桩与 Cloud 在出厂时预置的共享对称密钥（256位）
    const std::string shared_key = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    // ---- 初始化密码学工具 ----
    // 构造时自动初始化 secp256r1 椭圆曲线群和相关上下文
    CryptoUtils crypto;

    // ---- 第〇步：生成本地静态密钥对 (x_i, P_i = x_i·G) ----
    KeyMaterial static_key = crypto.generate_static_key();
    std::cout << "[Pile] 启动充电桩 Demo，静态公钥 P_i = " << static_key.public_hex << "\n";

    // ---- 建立 TCP 连接 ----
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

    // ========================================================================
    // 第一步：HMAC 挑战-响应认证
    //
    // Cloud 发送随机 nonce 挑战，充电桩使用预共享密钥计算 HMAC-SHA256
    // 并回送。此步骤证明充电桩持有合法的预共享密钥。
    // ========================================================================
    auto challenge = json_parse(read_line(fd));
    std::cout << "[Pile][Socket] 收到挑战报文: " << json_stringify(challenge) << "\n";
    std::string nonce = challenge["nonce"];
    write_line(fd, {
        {"type", "hmac"},
        {"id", pile_id},
        // 同时上报静态公钥，供 Cloud 后续使用的
        {"publicKey", static_key.public_hex},
        // HMAC-SHA256(预共享密钥, nonce) → 证明持有预共享密钥
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

    // ========================================================================
    // 第二步：通过 Cloud 透传向 KGC 申请部分私钥 d_i
    //
    // 充电桩将身份 ID 和静态公钥 P_i 发送给 Cloud，Cloud 转发给 KGC。
    // KGC 根据 (ID_i, P_i) 计算部分私钥 Q_partial = H2(ID_i||P_i) · s，
    // 并用 P_i 加密后通过 Cloud 返回。
    // 充电桩使用 ECIES 解密得到 Q_partial，计算派生标量 d_i = H2(Q_partial)，
    // 然后组装完整私钥 sk_i = x_i + d_i (mod n)。
    // ========================================================================
    write_line(fd, {
        {"type", "partial_key_request"},
        {"id", pile_id},
        {"publicKey", static_key.public_hex}
    });

    auto partial = json_parse(read_line(fd));
    std::cout << "[Pile][Socket] 收到部分私钥响应: " << json_stringify(partial) << "\n";
    // ECIES 解密：使用静态私钥 x_i 解密 KGC 加密的部分私钥
    const std::string decrypted_partial = crypto.ecies_decrypt(partial["partialPrivate"], static_key.secret_hex);
    // 从解密后的部分私钥 Q_partial 计算派生公钥 Y_i = d_i·G（d_i = H2(Q_partial)）
    const std::string derived_public = crypto.compute_derived_public(decrypted_partial);
    // 组装完整私钥 sk_i = x_i + d_i (mod n)
    const std::string full_private = crypto.compose_full_private(static_key.secret_hex, decrypted_partial);
    std::cout << "[Pile] 已 ECIES 解密部分私钥并根据 x_i + d_i 组装完整私钥 sk_i。\n";
    std::cout << "[Pile] 派生公钥 Y_i = " << derived_public << "\n";

    // ========================================================================
    // 第三步：生成临时 ECDH 密钥对，签名协商报文，发起密钥协商请求
    //
    // 充电桩生成临时密钥对 (a, RA = a·G)，构建 transcript = RA||IDA||WB||T，
    // 使用完整私钥 sk_i 做 Schnorr 签名，与 RA 和时间戳一同发送给 Cloud。
    // ========================================================================
    KeyMaterial eph = crypto.generate_static_key();  // 生成临时密钥对 (a, RA)
    std::string ta = now_iso8601();                  // 当前时间戳（用于防重放）
    // Schnorr 签名：sign(RA || ID_A || WB || T_A) with sk_i
    Signature sig = crypto.sign_transcript(eph.public_hex, pile_id, cloud_static_public, ta, full_private);
    std::cout << "[Pile] 生成临时公钥 RA = " << eph.public_hex << "\n";
    std::cout << "[Pile] 对协商报文进行签名，准备发起带认证的 ECDH。\n";
    write_line(fd, {
        {"type", "ka_request"},
        {"id", pile_id},
        // 静态公钥 P_i（供 Cloud 恢复完整公钥）
        {"publicKey", static_key.public_hex},
        // 派生公钥 Y_i（供 Cloud 计算 PK_i = P_i + Y_i）
        {"derivedPublic", derived_public},
        // 临时公钥 RA（用于 ECDH）
        {"ra", eph.public_hex},
        // 时间戳 T_A
        {"t", ta},
        // Schnorr 签名 σ = (R, s)
        {"sig", sig.to_hex()}
    });

    // ========================================================================
    // 第四步：接收 Cloud 的密钥协商响应，验证签名
    //
    // Cloud 同样生成临时密钥对 (b, RB = b·G)，构建 transcript = RB||IDB||WA||TB，
    // 签名后返回。充电桩需要：
    // 1. 使用 Cloud 静态公钥 + 派生公钥恢复 Cloud 完整公钥 PK_cloud = P_cloud + Y_cloud
    // 2. 使用 PK_cloud 验证 Cloud 的 Schnorr 签名
    // ========================================================================
    auto ka = json_parse(read_line(fd));
    std::cout << "[Pile][Socket] 收到协商响应: " << json_stringify(ka) << "\n";
    if (ka["type"] != "ka_response") {
        std::cerr << "[Pile] 密钥协商失败，Cloud 未返回有效响应。\n";
        return 1;
    }

    // 恢复 Cloud 的完整公钥：PK_cloud = P_cloud + Y_cloud
    const std::string cloud_full_public = crypto.derive_full_public(ka["publicKey"], ka["derivedPublic"]);
    // 验证 Cloud 的 Schnorr 签名：verify(RB || ID_cloud || WA || T_B)
    const bool ok = crypto.verify_transcript(ka["rb"], ka["id"], eph.public_hex, ka["t"], ka["sig"], cloud_full_public);
    if (!ok) {
        std::cerr << "[Pile] Cloud 签名校验失败，拒绝使用本次协商结果。\n";
        return 1;
    }
    std::cout << "[Pile] Cloud 签名校验通过。\n";

    // ========================================================================
    // 第五步：派生最终会话密钥
    //
    // 使用己方临时私钥 a 和 Cloud 临时公钥 RB 计算 ECDH 共享点 S = a·RB，
    // 提取 x 坐标，与完整绑定上下文（RA, RB, ID_A, ID_B, T_A, T_B）拼接后
    // SHA-256 哈希得到会话密钥。双方应得到相同的会话密钥。
    // ========================================================================
    const std::string session_key = crypto.derive_session_key(
        eph.secret_hex, ka["rb"],           // 己方临时私钥 a, 对端临时公钥 RB
        eph.public_hex, ka["rb"],           // RA, RB（绑定上下文）
        pile_id, ka["id"],                  // ID_A, ID_B
        ta, ka["t"]                         // T_A, T_B
    );
    std::cout << "[Pile] 会话密钥协商完成，会话密钥 = " << session_key << "\n";
    ::close(fd);
    return 0;
}
