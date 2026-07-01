package com.clpkc.kgc.api;

import jakarta.validation.Valid;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.clpkc.kgc.service.KgcService;

/**
 * KGC HTTP 接口。
 *
 * <ul>
 *   <li>{@code POST /api/v1/partial-key} — 颁发 ECIES 加密的部分私钥。</li>
 *   <li>{@code GET  /api/v1/system-params} — 查询曲线与主公钥。</li>
 * </ul>
 *
 * <p>说明：按当前阶段要求，KGC 走明文 HTTP、暂不做调用方鉴权，TLS 与访问控制
 * 交由后续 NGINX 网关统一处理。</p>
 */
@RestController
@RequestMapping("/api/v1")
public class KgcController {

    private final KgcService kgcService;

    public KgcController(KgcService kgcService) {
        this.kgcService = kgcService;
    }

    @PostMapping("/partial-key")
    public KgcService.PartialKey partialKey(@Valid @RequestBody PartialKeyRequest req) {
        return kgcService.issuePartialKey(req.getId(), req.getPublicKey());
    }

    @GetMapping("/system-params")
    public KgcService.SystemParams systemParams() {
        return kgcService.systemParams();
    }
}
