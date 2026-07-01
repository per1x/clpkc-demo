package com.clpkc.core.util;

/**
 * 十六进制编解码工具。
 *
 * <p>统一输出小写十六进制，与 C++ 充电桩侧 {@code bytes_to_hex} 保持一致，
 * 保证跨实现的字符串比较可直接进行。</p>
 */
public final class Hex {

    private static final char[] DIGITS = "0123456789abcdef".toCharArray();

    private Hex() {
    }

    /**
     * 将字节数组编码为小写十六进制字符串。
     *
     * @param data 原始字节
     * @return 长度为 {@code 2 * data.length} 的小写十六进制字符串
     */
    public static String encode(byte[] data) {
        char[] out = new char[data.length * 2];
        for (int i = 0; i < data.length; i++) {
            int v = data[i] & 0xff;
            out[i * 2] = DIGITS[v >>> 4];
            out[i * 2 + 1] = DIGITS[v & 0x0f];
        }
        return new String(out);
    }

    /**
     * 将十六进制字符串解码为字节数组。
     *
     * @param hex 十六进制字符串（大小写均可，长度必须为偶数）
     * @return 解码后的字节数组
     * @throws IllegalArgumentException 长度为奇数或含非法字符
     */
    public static byte[] decode(String hex) {
        int len = hex.length();
        if ((len & 1) != 0) {
            throw new IllegalArgumentException("hex length must be even: " + len);
        }
        byte[] out = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            int hi = Character.digit(hex.charAt(i), 16);
            int lo = Character.digit(hex.charAt(i + 1), 16);
            if (hi < 0 || lo < 0) {
                throw new IllegalArgumentException("invalid hex char at index " + i);
            }
            out[i / 2] = (byte) ((hi << 4) | lo);
        }
        return out;
    }
}
