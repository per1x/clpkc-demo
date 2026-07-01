package com.clpkc.cloud.service;

import java.math.BigInteger;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import com.clpkc.cloud.config.CloudProperties;
import com.clpkc.cloud.kgc.KgcClient;
import com.clpkc.core.ClpkcCrypto;
import com.clpkc.core.EcCurve;
import com.clpkc.core.util.Hex;

/**
 * 云平台自身的 CL-PKC 身份：静态密钥 + 向 KGC 申请的部分私钥组合出的完整密钥。
 *
 * <p>采用懒初始化并带重试语义：云平台可以先于 KGC 启动，首次需要时再向 KGC 申请，
 * 失败会抛出异常由调用方（连接处理）捕获，不影响服务存活。</p>
 */
@Service
public class CloudIdentity {

    private static final Logger log = LoggerFactory.getLogger(CloudIdentity.class);

    private final ClpkcCrypto crypto = new ClpkcCrypto();
    private final CloudProperties props;
    private final KgcClient kgcClient;
    private final byte[] sharedKey;

    private volatile boolean ready;
    private String id;
    private BigInteger staticSecret;
    private String staticPublicHex;
    private String derivedPublicHex;
    private BigInteger fullPrivate;
    private String fullPublicHex;

    public CloudIdentity(CloudProperties props, KgcClient kgcClient) {
        this.props = props;
        this.kgcClient = kgcClient;
        this.sharedKey = loadSharedKey(props.sharedKeyHex());
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

    public String staticPublicHex() {
        ensureReady();
        return staticPublicHex;
    }

    public String derivedPublicHex() {
        ensureReady();
        return derivedPublicHex;
    }

    public BigInteger fullPrivate() {
        ensureReady();
        return fullPrivate;
    }

    public String fullPublicHex() {
        ensureReady();
        return fullPublicHex;
    }

    /** 转发桩端的部分私钥申请到 KGC。 */
    public Map<String, String> forwardPartialKey(String pileId, String pilePublicKey) {
        return kgcClient.requestPartialKey(pileId, pilePublicKey);
    }

    private void ensureReady() {
        if (ready) {
            return;
        }
        synchronized (this) {
            if (ready) {
                return;
            }
            this.id = props.id();
            this.staticSecret = loadStaticSecret(props.staticSecretHex());
            this.staticPublicHex = Hex.encode(crypto.curve().encode(
                crypto.curve().basePointMul(staticSecret)));

            Map<String, String> resp = kgcClient.requestPartialKey(id, staticPublicHex);
            ClpkcCrypto.FullKey full = crypto.composeFullKey(staticSecret, resp.get("partialPrivate"));
            this.fullPrivate = full.privateScalar();
            this.derivedPublicHex = full.derivedPublicHex();
            this.fullPublicHex = crypto.deriveFullPublic(staticPublicHex, derivedPublicHex);
            this.ready = true;
            log.info("[Cloud] 身份就绪：id={}, 静态公钥 P_c={}, 完整公钥 PK_c={}",
                id, staticPublicHex, fullPublicHex);
        }
    }

    private BigInteger loadStaticSecret(String hex) {
        if (hex == null || hex.isBlank()) {
            BigInteger s = crypto.curve().randomScalar();
            log.warn("[Cloud] 未配置 clpkc.cloud.static-secret-hex，已临时随机生成静态私钥（重启即变）。"
                + "生产环境请固定该值。");
            return s;
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
