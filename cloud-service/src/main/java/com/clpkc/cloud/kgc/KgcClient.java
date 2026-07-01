package com.clpkc.cloud.kgc;

import java.time.Duration;
import java.util.Map;

import org.springframework.boot.web.client.ClientHttpRequestFactorySettings;
import org.springframework.boot.web.client.ClientHttpRequestFactories;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import com.clpkc.cloud.config.CloudProperties;

/**
 * KGC HTTP 客户端（带连接/读超时）。云平台把充电桩的部分私钥申请转发给 KGC。
 */
@Component
public class KgcClient {

    private final RestClient restClient;

    public KgcClient(CloudProperties props) {
        CloudProperties.Kgc cfg = props.kgc();
        ClientHttpRequestFactorySettings settings = ClientHttpRequestFactorySettings.DEFAULTS
            .withConnectTimeout(Duration.ofMillis(cfg.connectTimeoutMs()))
            .withReadTimeout(Duration.ofMillis(cfg.readTimeoutMs()));
        this.restClient = RestClient.builder()
            .baseUrl(cfg.baseUrl())
            .requestFactory(ClientHttpRequestFactories.get(settings))
            .build();
    }

    /**
     * 申请部分私钥。
     *
     * @return KGC 响应体：{@code {curve, partialPrivate, masterPublicKey}}
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
