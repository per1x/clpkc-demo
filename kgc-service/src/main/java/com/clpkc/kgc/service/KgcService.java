package com.clpkc.kgc.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.clpkc.kgc.config.KgcKeyStore;
import com.clpkc.kgc.crypto.ClpkcCrypto;

/**
 * KGC 核心业务（隐式证书方案）：颁发声明公钥 WA + SM2 加密的部分私钥 tA。
 *
 * <p>安全要点：主私钥仅驻留内存，日志不得输出主私钥或明文部分私钥。</p>
 */
@Service
public class KgcService {

    private static final Logger log = LoggerFactory.getLogger(KgcService.class);

    private final ClpkcCrypto crypto = new ClpkcCrypto();
    private final KgcKeyStore keyStore;
    private final String curveName;

    public KgcService(KgcKeyStore keyStore,
                      @Value("${clpkc.kgc.curve-name:sm2p256v1}") String curveName) {
        this.keyStore = keyStore;
        this.curveName = curveName;
    }

    /** 颁发部分私钥（WA + SM2 加密的 tA）。 */
    public PartialKey issuePartialKey(String id, String localPublicHex) {
        ClpkcCrypto.PartialKey pk = crypto.issuePartialKey(keyStore.masterSecret(), id, localPublicHex);
        log.info("[KGC] 已为 id={} 颁发声明公钥与部分私钥（密文 {} hex）", id, pk.encryptedPartialHex().length());
        return new PartialKey(curveName, pk.claimedPublicHex(), pk.encryptedPartialHex(), keyStore.masterPublicHex());
    }

    public SystemParams systemParams() {
        return new SystemParams(curveName, keyStore.masterPublicHex());
    }

    /** 部分私钥颁发结果（提供 getter 供 JSON 序列化）。 */
    public static final class PartialKey {
        private final String curve;
        private final String claimedPublic;
        private final String partialPrivate;
        private final String masterPublicKey;

        public PartialKey(String curve, String claimedPublic, String partialPrivate, String masterPublicKey) {
            this.curve = curve;
            this.claimedPublic = claimedPublic;
            this.partialPrivate = partialPrivate;
            this.masterPublicKey = masterPublicKey;
        }

        public String getCurve() {
            return curve;
        }

        public String getClaimedPublic() {
            return claimedPublic;
        }

        public String getPartialPrivate() {
            return partialPrivate;
        }

        public String getMasterPublicKey() {
            return masterPublicKey;
        }
    }

    /** 系统参数。 */
    public static final class SystemParams {
        private final String curve;
        private final String masterPublicKey;

        public SystemParams(String curve, String masterPublicKey) {
            this.curve = curve;
            this.masterPublicKey = masterPublicKey;
        }

        public String getCurve() {
            return curve;
        }

        public String getMasterPublicKey() {
            return masterPublicKey;
        }
    }
}
