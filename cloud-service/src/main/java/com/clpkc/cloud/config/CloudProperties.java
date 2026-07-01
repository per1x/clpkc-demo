package com.clpkc.cloud.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * 云平台配置项（前缀 {@code clpkc.cloud}）。
 *
 * @param id               云平台标识
 * @param staticSecretHex  云平台静态私钥 x_c（32 字节 hex）；留空则启动时随机生成并告警
 * @param sharedKeyHex     与充电桩的<b>全局</b>预共享密钥（HMAC 认证用，P0-5：外置到配置）
 * @param socket           对桩的 TCP Socket 服务端配置
 * @param kgc              对 KGC 的 HTTP 客户端配置
 */
@ConfigurationProperties(prefix = "clpkc.cloud")
public record CloudProperties(
    String id,
    String staticSecretHex,
    String sharedKeyHex,
    Socket socket,
    Kgc kgc
) {

    public CloudProperties {
        if (id == null || id.isBlank()) {
            id = "cloud-001";
        }
        if (socket == null) {
            socket = new Socket(0, 0, 0, 0);
        }
        if (kgc == null) {
            kgc = new Kgc(null, 0, 0);
        }
    }

    /**
     * @param port          Socket 监听端口
     * @param backlog       accept 队列长度
     * @param readTimeoutMs 单次读超时（毫秒），防止慢连接占用线程
     * @param maxThreads    处理连接的线程池上限
     */
    public record Socket(int port, int backlog, int readTimeoutMs, int maxThreads) {
        public Socket {
            if (port <= 0) {
                port = 9000;
            }
            if (backlog <= 0) {
                backlog = 128;
            }
            if (readTimeoutMs <= 0) {
                readTimeoutMs = 15000;
            }
            if (maxThreads <= 0) {
                maxThreads = 64;
            }
        }
    }

    /**
     * @param baseUrl          KGC 基础地址，如 http://127.0.0.1:8443
     * @param connectTimeoutMs 连接超时
     * @param readTimeoutMs    读超时
     */
    public record Kgc(String baseUrl, int connectTimeoutMs, int readTimeoutMs) {
        public Kgc {
            if (baseUrl == null || baseUrl.isBlank()) {
                baseUrl = "http://127.0.0.1:8443";
            }
            if (connectTimeoutMs <= 0) {
                connectTimeoutMs = 3000;
            }
            if (readTimeoutMs <= 0) {
                readTimeoutMs = 5000;
            }
        }
    }
}
