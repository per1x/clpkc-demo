#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "net_client.h"

// ============================================================================
// 桩 ↔ 云 二进制帧编解码。帧结构与假设见 docs/WIRE_PROTOCOL.md。
//   68 | 数据长度(2) | 序列号(2) | 加密标志(1) | 类型(1) | 主机编号(7 BCD) | 载荷 | CRC16(2)
// 多字节大端；数据长度=载荷字节数；CRC-16/CCITT-FALSE 覆盖 [起始..载荷末]。
// ============================================================================

namespace frame {

// 报文类型
constexpr uint8_t TYPE_P1_UP = 0x39;    // 一阶段 桩→云
constexpr uint8_t TYPE_P1_DOWN = 0x3A;  // 一阶段 云→桩
constexpr uint8_t TYPE_P2_UP = 0x3B;    // 二阶段 桩→云
constexpr uint8_t TYPE_P2_DOWN = 0x3C;  // 二阶段 云→桩

// 步骤号 STEP = 高4位轮次 | 低4位类别(1=请求,2=应答/回执)
constexpr uint8_t STEP_1_REQ = 0x11;
constexpr uint8_t STEP_1_RESP = 0x12;
constexpr uint8_t STEP_2_REQ = 0x21;
constexpr uint8_t STEP_2_RESP = 0x22;
constexpr uint8_t STEP_3_REQ = 0x31;
constexpr uint8_t STEP_3_RESP = 0x32;

constexpr uint8_t RESULT_OK = 0x00;
constexpr uint8_t RESULT_FAIL = 0x01;
constexpr uint8_t RECEIVED_YES = 0x01;

struct Frame {
    uint8_t type = 0;
    uint16_t seq = 0;
    uint8_t enc_flag = 0;
    std::vector<unsigned char> host_no;  // 7 字节 BCD
    std::vector<unsigned char> payload;  // 首字节为 STEP
};

// ---- 通用编码辅助 ----
std::vector<unsigned char> hex_to_bytes(const std::string& hex);
std::string bytes_to_hex(const std::vector<unsigned char>& data);
uint16_t crc16_ccitt(const std::vector<unsigned char>& data);   // CCITT-FALSE
std::vector<unsigned char> bcd7_from_id(const std::string& id);  // 主机编号 → 7B BCD
std::vector<unsigned char> cp56_now();                           // 7B CP56Time2a

// 组帧：type + seq + host_no + payload → 完整帧字节
std::vector<unsigned char> encode(uint8_t type, uint16_t seq,
                                  const std::vector<unsigned char>& host_no,
                                  const std::vector<unsigned char>& payload);

// 从连接读一帧（校验起始符与 CRC；失败抛 std::runtime_error）
Frame read(NetClient& net);

// ---- 载荷顺序读取器（定长字段直拼）----
class Reader {
public:
    explicit Reader(const std::vector<unsigned char>& buf) : buf_(buf) {}
    uint8_t u8();
    std::vector<unsigned char> take(std::size_t n);
    std::string take_hex(std::size_t n);
    std::size_t remaining() const { return buf_.size() - pos_; }

private:
    const std::vector<unsigned char>& buf_;
    std::size_t pos_ = 0;
};

}  // namespace frame
