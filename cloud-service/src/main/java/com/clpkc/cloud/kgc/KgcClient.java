package com.clpkc.cloud.kgc;

import java.time.Duration;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.client.ClientHttpRequestFactories;
import org.springframework.boot.web.client.ClientHttpRequestFactorySettings;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

/**
 * KGC HTTP 客户端（带连接/读超时）。云平台把充电桩的部分私钥申请转发给 KGC。
 * 配置通过 {@code @Value} 从 {@code .properties} 读取。
 */
@Component
public class KgcClient {

    private final RestClient restClient;

    public KgcClient(@Value("${clpkc.cloud.kgc.base-url:http://127.0.0.1:8443}") String baseUrl,
                     @Value("${clpkc.cloud.kgc.connect-timeout-ms:3000}") int connectTimeoutMs,
                     @Value("${clpkc.cloud.kgc.read-timeout-ms:5000}") int readTimeoutMs) {
        ClientHttpRequestFactorySettings settings = ClientHttpRequestFactorySettings.DEFAULTS
            .withConnectTimeout(Duration.ofMillis(connectTimeoutMs))
            .withReadTimeout(Duration.ofMillis(readTimeoutMs));
        this.restClient = RestClient.builder()
            .baseUrl(baseUrl)
            .requestFactory(ClientHttpRequestFactories.get(settings))
            .build();
    }

    /**
     * 申请部分私钥。
     *
     * @return KGC 响应体：{@code {curve, claimedPublic, partialPrivate, masterPublicKey}}
     */
    @SuppressWarnings("unchecked")
    public Map<String, String> requestPartialKey(String id, String publicKeyHex) {
        return restClient.post()
            .uri("/api/v1/partial-key")
            .contentType(MediaType.APPLICATION_JSON)
            .body(Map.of("id", id, "publicKey", publicKeyHex))
            .retrieve()
            .body(Map.class);
    }
}
