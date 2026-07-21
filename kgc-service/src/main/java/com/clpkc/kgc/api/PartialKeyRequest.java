package com.clpkc.kgc.api;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

/**
 * 部分私钥申请入参（JavaBean，供 Jackson 反序列化 + 校验）。
 *
 * <ul>
 *   <li>{@code id}：申请方标识，**32 字节 ID 的 64 hex**（桩=BCD 主机编号，云=域名 ASCII 补 0x00）。</li>
 *   <li>{@code publicKey}：申请方本地公钥 UA，128 hex（x‖y，无 04 前缀）。</li>
 * </ul>
 */
public class PartialKeyRequest {

    @NotBlank(message = "id 不能为空")
    @Pattern(regexp = "^[0-9a-fA-F]{64}$", message = "id 必须为 64 hex（32 字节 ID）")
    private String id;

    @NotBlank(message = "publicKey 不能为空")
    @Pattern(regexp = "^[0-9a-fA-F]{128}$", message = "publicKey 必须为 128 hex（x‖y 坐标）")
    private String publicKey;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }
}
