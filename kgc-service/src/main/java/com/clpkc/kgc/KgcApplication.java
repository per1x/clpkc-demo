package com.clpkc.kgc;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

import com.clpkc.kgc.config.KgcProperties;

/**
 * KGC（密钥生成中心）服务入口。
 *
 * <p>对外提供 HTTP 接口：部分私钥颁发、系统参数查询。主私钥由配置注入
 * （见 {@link KgcProperties}），不再每次启动随机生成。</p>
 */
@SpringBootApplication
@EnableConfigurationProperties(KgcProperties.class)
public class KgcApplication {
    public static void main(String[] args) {
        SpringApplication.run(KgcApplication.class, args);
    }
}
