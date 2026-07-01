package com.clpkc.cloud;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * 云平台服务入口。
 *
 * <p>同时承担两个角色：对 KGC 为 HTTP 客户端；对充电桩为 TCP Socket 服务端
 * （长连接）。Socket 服务端由 {@code PileSocketServer} 在应用启动后拉起。
 * 配置均通过 {@code @Value} 直接从 {@code .properties} 读取。</p>
 */
@SpringBootApplication
public class CloudApplication {
    public static void main(String[] args) {
        SpringApplication.run(CloudApplication.class, args);
    }
}
