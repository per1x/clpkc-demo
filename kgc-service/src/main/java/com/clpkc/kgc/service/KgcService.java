package com.clpkc.kgc.service;

import java.math.BigInteger;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import com.clpkc.core.ClpkcCrypto;
import com.clpkc.core.EcCurve;
import com.clpkc.core.util.Hex;
import com.clpkc.kgc.config.KgcProperties;

/**
 * KGC 核心业务：加载主私钥、颁发 ECIES 加密的部分私钥、返回系统参数。
 *
 * <p>安全要点：主私钥仅驻留内存，任何日志<b>不得</b>输出主私钥或其派生的明文部分私钥。</p>
 */
@Service
public class KgcService {

    private static final Logger log = LoggerFactory.getLogger(KgcService.class);

    private final ClpkcCrypto crypto = new ClpkcCrypto();
    private final BigInteger masterSecret;
    private final String masterPublicHex;
    private final String curveName;

    public KgcService(KgcProperties props) {
        this.curveName = props.curveName();
        this.masterSecret = loadMasterSecret(props.masterSecretHex());
        this.masterPublicHex = crypto.masterPublicHex(masterSecret);
        log.info("[KGC] 主密钥已加载，主公钥 Ppub = {}", masterPublicHex);
    }

    /** 颁发部分私钥（ECIES 加密）。 */
    public PartialKey issuePartialKey(String id, String publicKeyHex) {
        byte[] partialPoint = crypto.issuePartialPrivate(masterSecret, id, publicKeyHex);
        String encrypted = crypto.sm2Encrypt(partialPoint, publicKeyHex);
        log.info("[KGC] 已为 id={} 颁发部分私钥（密文长度 {} hex）", id, encrypted.length());
        return new PartialKey(curveName, encrypted, masterPublicHex);
    }

    public SystemParams systemParams() {
        return new SystemParams(curveName, masterPublicHex);
    }

    private BigInteger loadMasterSecret(String hex) {
        if (hex == null || hex.isBlank()) {
            BigInteger generated = crypto.curve().randomScalar();
            log.warn("[KGC] 未配置 clpkc.kgc.master-secret-hex，已临时随机生成主密钥。"
                + "重启将导致所有已颁发密钥失效——生产环境必须在配置中固定该值：{}",
                Hex.encode(crypto.curve().toFixed(generated, EcCurve.SCALAR_LEN)));
            return generated;
        }
        BigInteger s = new BigInteger(1, Hex.decode(hex.trim()));
        if (s.signum() <= 0 || s.compareTo(EcCurve.N) >= 0) {
            throw new IllegalStateException("clpkc.kgc.master-secret-hex 不在 [1, N-1] 范围内");
        }
        return s;
    }

    /** 部分私钥颁发结果。 */
    public record PartialKey(String curve, String partialPrivate, String masterPublicKey) {
    }

    /** 系统参数。 */
    public record SystemParams(String curve, String masterPublicKey) {
    }
}
