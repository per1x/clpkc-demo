package com.clpkc.kgc.api;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

/**
 * 部分私钥申请入参。
 *
 * @param id        申请方标识（设备/平台）
 * @param publicKey 申请方静态公钥 P_i，SEC1 非压缩十六进制（130 字符，0x04 前缀）
 */
public record PartialKeyRequest(
    @NotBlank(message = "id 不能为空")
    String id,

    @NotBlank(message = "publicKey 不能为空")
    @Pattern(regexp = "^04[0-9a-fA-F]{128}$", message = "publicKey 必须为 SEC1 非压缩十六进制（130 字符）")
    String publicKey
) {
}
