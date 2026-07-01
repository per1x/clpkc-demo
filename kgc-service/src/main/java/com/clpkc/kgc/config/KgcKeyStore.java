package com.clpkc.kgc.config;

import java.math.BigInteger;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.clpkc.kgc.crypto.ClpkcCrypto;
import com.clpkc.kgc.crypto.EcCurve;
import com.clpkc.kgc.crypto.Hex;

/**
 * KGC 主密钥：直接从 {@code .properties} 配置项 {@code clpkc.kgc.master-secret-hex} 读取。
 *
 * <p>内容为 32 字节大端主私钥的十六进制（64 字符）。安全说明：生产环境请通过环境变量 /
 * 外部配置中心覆盖，切勿把真实主私钥提交到代码仓库。</p>
 */
@Component
public class KgcKeyStore {

    private static final Logger log = LoggerFactory.getLogger(KgcKeyStore.class);

    private final BigInteger masterSecret;
    private final String masterPublicHex;

    public KgcKeyStore(@Value("${clpkc.kgc.master-secret-hex}") String masterSecretHex) {
        if (masterSecretHex == null || masterSecretHex.isBlank()) {
            throw new IllegalStateException("必须在配置文件中设置 clpkc.kgc.master-secret-hex");
        }
        BigInteger s = new BigInteger(1, Hex.decode(masterSecretHex.trim()));
        if (s.signum() <= 0 || s.compareTo(EcCurve.N) >= 0) {
            throw new IllegalStateException("clpkc.kgc.master-secret-hex 不在 [1, N-1] 范围内");
        }
        this.masterSecret = s;
        this.masterPublicHex = new ClpkcCrypto().masterPublicHex(s);
        log.info("[KGC] 主密钥已从配置加载，主公钥 Ppub = {}", masterPublicHex);
    }

    public BigInteger masterSecret() {
        return masterSecret;
    }

    public String masterPublicHex() {
        return masterPublicHex;
    }
}
