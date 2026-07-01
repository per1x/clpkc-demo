package com.clpkc.kgc;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * KGC（密钥生成中心）服务入口。
 *
 * <p>对外提供 HTTP 接口：颁发声明公钥 + SM2 加密的部分私钥、查询系统参数。
 * 主私钥直接从 {@code .properties} 配置读取（见 {@code KgcKeyStore}）。</p>
 */
@SpringBootApplication
public class KgcApplication {
    public static void main(String[] args) {
        SpringApplication.run(KgcApplication.class, args);
    }
}
