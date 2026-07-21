package com.clpkc.cloud.service;

import java.math.BigInteger;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.clpkc.cloud.crypto.ClpkcCrypto;
import com.clpkc.cloud.crypto.EcCurve;
import com.clpkc.cloud.crypto.Hex;
import com.clpkc.cloud.kgc.KgcClient;

/**
 * 云平台自身的无证书身份（隐式证书方案）：本地密钥 + 向 KGC 申请的部分私钥组合出完整密钥。
 *
 * <p>懒初始化：云平台可先于 KGC 启动，首次需要时再申请。</p>
 */
@Service
public class CloudIdentity {

    private static final Logger log = LoggerFactory.getLogger(CloudIdentity.class);

    private final ClpkcCrypto crypto = new ClpkcCrypto();
    private final KgcClient kgcClient;
    private final String configuredId;
    private final String staticSecretHex;
    private final byte[] sharedKey;

    private volatile boolean ready;
    private String id;
    private String claimedPublicHex;   // WA_c
    private BigInteger fullPrivate;     // dA_c
    private String fullPublicHex;       // PA_c = dA_c·G = WA_c + λ·Ppub
    private String masterPublicHex;     // Ppub

    public CloudIdentity(KgcClient kgcClient,
                         @Value("${clpkc.cloud.id:cloud.example.com}") String id,
                         @Value("${clpkc.cloud.static-secret-hex:}") String staticSecretHex,
                         @Value("${clpkc.cloud.shared-key-hex:}") String sharedKeyHex) {
        this.kgcClient = kgcClient;
        this.configuredId = id;
        this.staticSecretHex = staticSecretHex;
        this.sharedKey = loadSharedKey(sharedKeyHex);
    }

    public ClpkcCrypto crypto() {
        return crypto;
    }

    public byte[] sharedKey() {
        return sharedKey.clone();
    }

    public String id() {
        ensureReady();
        return id;
    }

    /** 云平台声明公钥 WA_c（供桩重构 PA_c 验签，128 hex）。 */
    public String claimedPublicHex() {
        ensureReady();
        return claimedPublicHex;
    }

    /** 云平台完整私钥 dA_c（签名用）。 */
    public BigInteger fullPrivate() {
        ensureReady();
        return fullPrivate;
    }

    public String fullPublicHex() {
        ensureReady();
        return fullPublicHex;
    }

    /** KGC 主公钥 Ppub（重构对端公钥用）。 */
    public String masterPublicHex() {
        ensureReady();
        return masterPublicHex;
    }

    /** 转发桩的部分私钥申请到 KGC。 */
    public Map<String, String> forwardPartialKey(String pileId, String pileLocalPublic) {
        return kgcClient.requestPartialKey(pileId, pileLocalPublic);
    }

    private void ensureReady() {
        if (ready) {
            return;
        }
        synchronized (this) {
            if (ready) {
                return;
            }
            // ID_A = 域名 ASCII ‖ 0x00 补齐到 32 字节；对外一律传 64 字符 hex
            this.id = ClpkcCrypto.idHexFromAscii(configuredId);
            BigInteger ua = loadStaticSecret(staticSecretHex);
            String uaHex = crypto.curve().xyHex(crypto.curve().basePointMul(ua));

            Map<String, String> resp = kgcClient.requestPartialKey(id, uaHex);
            this.masterPublicHex = resp.get("masterPublicKey");
            this.claimedPublicHex = resp.get("claimedPublic");
            this.fullPrivate = crypto.composeFullPrivate(ua, resp.get("partialPrivate"));
            this.fullPublicHex = crypto.reconstructFullPublicHex(id, claimedPublicHex, masterPublicHex);
            this.ready = true;
            log.info("[Cloud] 身份就绪：域名={} → ID_A(32B hex)={}, 声明公钥 WA_c={}, 完整公钥 PK_c={}",
                configuredId, id, claimedPublicHex, fullPublicHex);
        }
    }

    private BigInteger loadStaticSecret(String hex) {
        if (hex == null || hex.isBlank()) {
            log.warn("[Cloud] 未配置 clpkc.cloud.static-secret-hex，已临时随机生成静态私钥（重启即变）。");
            return crypto.curve().randomScalar();
        }
        BigInteger s = new BigInteger(1, Hex.decode(hex.trim()));
        if (s.signum() <= 0 || s.compareTo(EcCurve.N) >= 0) {
            throw new IllegalStateException("clpkc.cloud.static-secret-hex 不在 [1, N-1] 范围内");
        }
        return s;
    }

    private byte[] loadSharedKey(String hex) {
        if (hex == null || hex.isBlank()) {
            throw new IllegalStateException("必须配置 clpkc.cloud.shared-key-hex（与充电桩的全局预共享密钥）");
        }
        return Hex.decode(hex.trim());
    }
}
