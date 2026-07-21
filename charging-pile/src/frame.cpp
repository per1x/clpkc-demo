#include "frame.h"

#include <ctime>
#include <stdexcept>

namespace frame {

namespace {
constexpr uint8_t START = 0x68;
constexpr std::size_t HEADER_LEN = 14;  // 起始..主机编号末
constexpr std::size_t FCS_LEN = 2;
constexpr std::size_t MAX_PAYLOAD = 8 * 1024;

int hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    throw std::runtime_error("非法 hex 字符");
}
}  // namespace

std::vector<unsigned char> hex_to_bytes(const std::string& hex) {
    if (hex.size() % 2 != 0) {
        throw std::runtime_error("hex 长度非偶");
    }
    std::vector<unsigned char> out;
    out.reserve(hex.size() / 2);
    for (std::size_t i = 0; i < hex.size(); i += 2) {
        out.push_back(static_cast<unsigned char>((hex_val(hex[i]) << 4) | hex_val(hex[i + 1])));
    }
    return out;
}

std::string bytes_to_hex(const std::vector<unsigned char>& data) {
    static const char* d = "0123456789abcdef";
    std::string out;
    out.reserve(data.size() * 2);
    for (unsigned char b : data) {
        out.push_back(d[b >> 4]);
        out.push_back(d[b & 0x0f]);
    }
    return out;
}

// CRC-16/CCITT-FALSE：poly=0x1021, init=0xFFFF, 不反转, xorout=0
uint16_t crc16_ccitt(const std::vector<unsigned char>& data) {
    uint16_t crc = 0xFFFF;
    for (unsigned char b : data) {
        crc ^= static_cast<uint16_t>(b) << 8;
        for (int i = 0; i < 8; i++) {
            if (crc & 0x8000) {
                crc = static_cast<uint16_t>((crc << 1) ^ 0x1021);
            } else {
                crc = static_cast<uint16_t>(crc << 1);
            }
        }
    }
    return crc;
}

// 主机编号 → 7 字节 BCD：取 id 中的数字，右对齐成 14 位十进制再压 BCD
std::vector<unsigned char> bcd7_from_id(const std::string& id) {
    std::string digits;
    for (char c : id) {
        if (c >= '0' && c <= '9') digits.push_back(c);
    }
    if (digits.size() > 14) {
        digits = digits.substr(digits.size() - 14);
    }
    while (digits.size() < 14) {
        digits.insert(digits.begin(), '0');
    }
    std::vector<unsigned char> out(7, 0);
    for (std::size_t i = 0; i < 7; i++) {
        out[i] = static_cast<unsigned char>(((digits[2 * i] - '0') << 4) | (digits[2 * i + 1] - '0'));
    }
    return out;
}

// CP56Time2a：毫秒(2) 分(1) 时(1) 日(1) 月(1) 年(1)
std::vector<unsigned char> cp56_now() {
    std::time_t t = std::time(nullptr);
    std::tm tm{};
    localtime_r(&t, &tm);
    unsigned int ms = static_cast<unsigned int>(tm.tm_sec) * 1000;
    std::vector<unsigned char> out(7, 0);
    out[0] = static_cast<unsigned char>(ms & 0xff);
    out[1] = static_cast<unsigned char>((ms >> 8) & 0xff);
    out[2] = static_cast<unsigned char>(tm.tm_min & 0x3f);
    out[3] = static_cast<unsigned char>(tm.tm_hour & 0x1f);
    out[4] = static_cast<unsigned char>(tm.tm_mday & 0x1f);
    out[5] = static_cast<unsigned char>((tm.tm_mon + 1) & 0x0f);
    out[6] = static_cast<unsigned char>(tm.tm_year % 100);
    return out;
}

std::vector<unsigned char> encode(uint8_t type, uint16_t seq,
                                  const std::vector<unsigned char>& host_no,
                                  const std::vector<unsigned char>& payload) {
    if (host_no.size() != 7) {
        throw std::runtime_error("主机编号必须 7 字节");
    }
    if (payload.size() > MAX_PAYLOAD) {
        throw std::runtime_error("载荷超长");
    }
    std::vector<unsigned char> f;
    f.reserve(HEADER_LEN + payload.size() + FCS_LEN);
    f.push_back(START);
    f.push_back(static_cast<unsigned char>((payload.size() >> 8) & 0xff));
    f.push_back(static_cast<unsigned char>(payload.size() & 0xff));
    f.push_back(static_cast<unsigned char>((seq >> 8) & 0xff));
    f.push_back(static_cast<unsigned char>(seq & 0xff));
    f.push_back(0x00);  // 加密标志：协商阶段明文
    f.push_back(type);
    f.insert(f.end(), host_no.begin(), host_no.end());
    f.insert(f.end(), payload.begin(), payload.end());
    uint16_t crc = crc16_ccitt(f);
    f.push_back(static_cast<unsigned char>((crc >> 8) & 0xff));
    f.push_back(static_cast<unsigned char>(crc & 0xff));
    return f;
}

Frame read(NetClient& net) {
    auto head = net.read_exact(HEADER_LEN);
    if (head[0] != START) {
        throw std::runtime_error("帧起始符非法");
    }
    std::size_t plen = (static_cast<std::size_t>(head[1]) << 8) | head[2];
    if (plen > MAX_PAYLOAD) {
        throw std::runtime_error("帧载荷超长");
    }
    auto payload = net.read_exact(plen);
    auto fcs = net.read_exact(FCS_LEN);

    std::vector<unsigned char> covered = head;
    covered.insert(covered.end(), payload.begin(), payload.end());
    uint16_t got = static_cast<uint16_t>((fcs[0] << 8) | fcs[1]);
    if (got != crc16_ccitt(covered)) {
        throw std::runtime_error("帧校验(CRC16)失败");
    }

    Frame fr;
    fr.seq = static_cast<uint16_t>((head[3] << 8) | head[4]);
    fr.enc_flag = head[5];
    fr.type = head[6];
    fr.host_no.assign(head.begin() + 7, head.begin() + 14);
    fr.payload = std::move(payload);
    return fr;
}

uint8_t Reader::u8() {
    if (pos_ + 1 > buf_.size()) {
        throw std::runtime_error("载荷读取越界(u8)");
    }
    return buf_[pos_++];
}

std::vector<unsigned char> Reader::take(std::size_t n) {
    if (pos_ + n > buf_.size()) {
        throw std::runtime_error("载荷读取越界");
    }
    std::vector<unsigned char> out(buf_.begin() + pos_, buf_.begin() + pos_ + n);
    pos_ += n;
    return out;
}

std::string Reader::take_hex(std::size_t n) {
    return bytes_to_hex(take(n));
}

}  // namespace frame
