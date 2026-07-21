package com.clpkc.cloud.socket;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.time.LocalDateTime;
import java.util.Arrays;

/**
 * 桩 ↔ 云 二进制帧编解码（与 charging-pile/src/frame.{h,cpp} 字节级对齐）。
 * 帧结构与假设见 docs/WIRE_PROTOCOL.md：
 *   68 | 数据长度(2) | 序列号(2) | 加密标志(1) | 类型(1) | 主机编号(7 BCD) | 载荷 | CRC16(2)
 * 多字节大端；数据长度=载荷字节数；CRC-16/CCITT-FALSE 覆盖 [起始..载荷末]。
 */
final class Frame {

    // 报文类型
    static final int TYPE_P1_UP = 0x39;    // 一阶段 桩→云
    static final int TYPE_P1_DOWN = 0x3A;  // 一阶段 云→桩
    static final int TYPE_P2_UP = 0x3B;    // 二阶段 桩→云
    static final int TYPE_P2_DOWN = 0x3C;  // 二阶段 云→桩

    // 步骤号 STEP = 高4位轮次 | 低4位类别(1=请求,2=应答/回执)
    static final int STEP_1_REQ = 0x11;
    static final int STEP_1_RESP = 0x12;
    static final int STEP_2_REQ = 0x21;
    static final int STEP_2_RESP = 0x22;
    static final int STEP_3_REQ = 0x31;
    static final int STEP_3_RESP = 0x32;

    static final int RESULT_OK = 0x00;
    static final int RESULT_FAIL = 0x01;
    static final int RECEIVED_YES = 0x01;

    private static final int START = 0x68;
    private static final int HEADER_LEN = 14;
    private static final int FCS_LEN = 2;
    private static final int MAX_PAYLOAD = 8 * 1024;

    final int type;
    final int seq;
    final int encFlag;
    final byte[] hostNo;   // 7 字节 BCD
    final byte[] payload;  // 首字节为 STEP

    private Frame(int type, int seq, int encFlag, byte[] hostNo, byte[] payload) {
        this.type = type;
        this.seq = seq;
        this.encFlag = encFlag;
        this.hostNo = hostNo;
        this.payload = payload;
    }

    // ---- CRC-16/CCITT-FALSE：poly=0x1021, init=0xFFFF, 不反转, xorout=0 ----
    static int crc16(byte[] data, int len) {
        int crc = 0xFFFF;
        for (int i = 0; i < len; i++) {
            crc ^= (data[i] & 0xff) << 8;
            for (int b = 0; b < 8; b++) {
                if ((crc & 0x8000) != 0) {
                    crc = (crc << 1) ^ 0x1021;
                } else {
                    crc <<= 1;
                }
                crc &= 0xFFFF;
            }
        }
        return crc & 0xFFFF;
    }

    // 主机编号 → 7 字节 BCD：取 id 中的数字，右对齐成 14 位十进制再压 BCD
    static byte[] bcd7FromId(String id) {
        StringBuilder digits = new StringBuilder();
        for (int i = 0; i < id.length(); i++) {
            char c = id.charAt(i);
            if (c >= '0' && c <= '9') {
                digits.append(c);
            }
        }
        String s = digits.toString();
        if (s.length() > 14) {
            s = s.substring(s.length() - 14);
        }
        while (s.length() < 14) {
            s = "0" + s;
        }
        byte[] out = new byte[7];
        for (int i = 0; i < 7; i++) {
            out[i] = (byte) (((s.charAt(2 * i) - '0') << 4) | (s.charAt(2 * i + 1) - '0'));
        }
        return out;
    }

    // CP56Time2a：毫秒(2) 分(1) 时(1) 日(1) 月(1) 年(1)
    static byte[] cp56Now() {
        LocalDateTime now = LocalDateTime.now();
        int ms = now.getSecond() * 1000;
        byte[] out = new byte[7];
        out[0] = (byte) (ms & 0xff);
        out[1] = (byte) ((ms >> 8) & 0xff);
        out[2] = (byte) (now.getMinute() & 0x3f);
        out[3] = (byte) (now.getHour() & 0x1f);
        out[4] = (byte) (now.getDayOfMonth() & 0x1f);
        out[5] = (byte) (now.getMonthValue() & 0x0f);
        out[6] = (byte) (now.getYear() % 100);
        return out;
    }

    /** 组帧：type + seq + hostNo + payload → 完整帧字节。 */
    static byte[] encode(int type, int seq, byte[] hostNo, byte[] payload) {
        if (hostNo.length != 7) {
            throw new IllegalArgumentException("主机编号必须 7 字节");
        }
        if (payload.length > MAX_PAYLOAD) {
            throw new IllegalArgumentException("载荷超长");
        }
        byte[] f = new byte[HEADER_LEN + payload.length + FCS_LEN];
        int i = 0;
        f[i++] = (byte) START;
        f[i++] = (byte) ((payload.length >> 8) & 0xff);
        f[i++] = (byte) (payload.length & 0xff);
        f[i++] = (byte) ((seq >> 8) & 0xff);
        f[i++] = (byte) (seq & 0xff);
        f[i++] = 0x00;  // 加密标志：协商阶段明文
        f[i++] = (byte) type;
        System.arraycopy(hostNo, 0, f, i, 7);
        i += 7;
        System.arraycopy(payload, 0, f, i, payload.length);
        i += payload.length;
        int crc = crc16(f, i);
        f[i++] = (byte) ((crc >> 8) & 0xff);
        f[i] = (byte) (crc & 0xff);
        return f;
    }

    /** 从流读一帧（校验起始符与 CRC；失败抛 IOException）。 */
    static Frame read(InputStream in) throws IOException {
        byte[] head = readExact(in, HEADER_LEN);
        if ((head[0] & 0xff) != START) {
            throw new IOException("帧起始符非法");
        }
        int plen = ((head[1] & 0xff) << 8) | (head[2] & 0xff);
        if (plen > MAX_PAYLOAD) {
            throw new IOException("帧载荷超长");
        }
        byte[] payload = readExact(in, plen);
        byte[] fcs = readExact(in, FCS_LEN);

        byte[] covered = new byte[HEADER_LEN + plen];
        System.arraycopy(head, 0, covered, 0, HEADER_LEN);
        System.arraycopy(payload, 0, covered, HEADER_LEN, plen);
        int got = ((fcs[0] & 0xff) << 8) | (fcs[1] & 0xff);
        if (got != crc16(covered, covered.length)) {
            throw new IOException("帧校验(CRC16)失败");
        }
        int seq = ((head[3] & 0xff) << 8) | (head[4] & 0xff);
        int enc = head[5] & 0xff;
        int type = head[6] & 0xff;
        byte[] hostNo = Arrays.copyOfRange(head, 7, 14);
        return new Frame(type, seq, enc, hostNo, payload);
    }

    static void write(OutputStream out, byte[] frame) throws IOException {
        out.write(frame);
        out.flush();
    }

    private static byte[] readExact(InputStream in, int len) throws IOException {
        byte[] out = new byte[len];
        int off = 0;
        while (off < len) {
            int n = in.read(out, off, len - off);
            if (n < 0) {
                throw new IOException("连接被对端关闭");
            }
            off += n;
        }
        return out;
    }

    /** 载荷顺序读取器（定长字段直拼）。 */
    static final class Reader {
        private final byte[] buf;
        private int pos;

        Reader(byte[] buf) {
            this.buf = buf;
        }

        int u8() {
            if (pos + 1 > buf.length) {
                throw new IllegalStateException("载荷读取越界(u8)");
            }
            return buf[pos++] & 0xff;
        }

        byte[] take(int n) {
            if (pos + n > buf.length) {
                throw new IllegalStateException("载荷读取越界");
            }
            byte[] out = Arrays.copyOfRange(buf, pos, pos + n);
            pos += n;
            return out;
        }
    }

    /** 载荷顺序写入器。 */
    static final class Writer {
        private final ByteArrayOutputStream buf = new ByteArrayOutputStream(256);

        Writer step(int step) {
            buf.write(step & 0xff);
            return this;
        }

        Writer u8(int v) {
            buf.write(v & 0xff);
            return this;
        }

        Writer bytes(byte[] b) {
            buf.write(b, 0, b.length);
            return this;
        }

        byte[] toArray() {
            return buf.toByteArray();
        }
    }
}
