package com.clpkc.kgc.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * KGC 配置项（前缀 {@code clpkc.kgc}）。
 *
 * @param masterSecretHex KGC 主私钥 s，32 字节大端十六进制（64 字符）。
 *                        <b>P0-4 要求：主密钥从配置注入而非每次随机生成。</b>
 *                        生产环境应通过环境变量 / 外部配置中心覆盖，切勿使用示例值。
 * @param curveName       曲线名称，仅用于响应回显，默认 secp256r1。
 */
@ConfigurationProperties(prefix = "clpkc.kgc")
public record KgcProperties(String masterSecretHex, String curveName) {

    public KgcProperties {
        if (curveName == null || curveName.isBlank()) {
            curveName = "secp256r1";
        }
    }
}
