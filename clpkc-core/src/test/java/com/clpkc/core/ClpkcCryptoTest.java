package com.clpkc.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.Test;

import com.clpkc.core.util.Hex;

/**
 * CL-PKC 协议原语自洽性测试：完整走一遍 KGC 颁发 → 桩端组合 → 双向签名 → 会话密钥协商。
 */
class ClpkcCryptoTest {

    private final ClpkcCrypto crypto = new ClpkcCrypto();

    @Test
    void fullHandshakeIsConsistent() {
        // KGC 主密钥（生产环境来自配置）
        BigInteger masterSecret = crypto.curve().randomScalar();

        // 两端静态密钥
        ClpkcCrypto.KeyMaterial pile = crypto.generateStaticKey();
        ClpkcCrypto.KeyMaterial cloud = crypto.generateStaticKey();
        String pileId = "pile-001";
        String cloudId = "cloud-001";

        // KGC 为两端颁发部分私钥并 ECIES 加密
        byte[] pilePartial = crypto.issuePartialPrivate(masterSecret, pileId, pile.publicKeyHex());
        byte[] cloudPartial = crypto.issuePartialPrivate(masterSecret, cloudId, cloud.publicKeyHex());
        String pileEnc = crypto.eciesEncrypt(pilePartial, pile.publicKeyHex());
        String cloudEnc = crypto.eciesEncrypt(cloudPartial, cloud.publicKeyHex());

        // 两端组合完整密钥
        ClpkcCrypto.FullKey pileKey = crypto.composeFullKey(pile.secretScalar(), pileEnc);
        ClpkcCrypto.FullKey cloudKey = crypto.composeFullKey(cloud.secretScalar(), cloudEnc);

        // 完整公钥自洽：PK = P + Y == sk·G
        String pilePk = crypto.deriveFullPublic(pile.publicKeyHex(), pileKey.derivedPublicHex());
        ECPoint pilePkPoint = crypto.curve().decode(Hex.decode(pilePk));
        ECPoint skG = crypto.curve().basePointMul(pileKey.privateScalar());
        assertEquals(skG, crypto.curve().decode(Hex.decode(pilePk)));
        assertTrue(pilePkPoint.equals(skG));

        String cloudPk = crypto.deriveFullPublic(cloud.publicKeyHex(), cloudKey.derivedPublicHex());

        // 握手 nonce（Cloud 下发）
        String nonce = Hex.encode(EcCurve.sha256("session-nonce".getBytes(StandardCharsets.UTF_8)));

        // KA：pile 生成临时对 (a, RA)，对 (RA, pileId, cloudStaticPub, nonce) 签名
        ClpkcCrypto.KeyMaterial ephA = crypto.generateStaticKey();
        ClpkcCrypto.Signature sigA = crypto.sign(Hex.decode(ephA.publicKeyHex()), pileId,
            Hex.decode(cloud.publicKeyHex()), nonce, pileKey.privateScalar());
        assertTrue(crypto.verify(Hex.decode(ephA.publicKeyHex()), pileId,
            Hex.decode(cloud.publicKeyHex()), nonce, sigA.toHex(), pilePk));

        // Cloud 生成 (b, RB)，对 (RB, cloudId, RA, nonce) 签名
        ClpkcCrypto.KeyMaterial ephB = crypto.generateStaticKey();
        ClpkcCrypto.Signature sigB = crypto.sign(Hex.decode(ephB.publicKeyHex()), cloudId,
            Hex.decode(ephA.publicKeyHex()), nonce, cloudKey.privateScalar());
        assertTrue(crypto.verify(Hex.decode(ephB.publicKeyHex()), cloudId,
            Hex.decode(ephA.publicKeyHex()), nonce, sigB.toHex(), cloudPk));

        // 篡改 nonce 应导致验签失败
        assertFalse(crypto.verify(Hex.decode(ephB.publicKeyHex()), cloudId,
            Hex.decode(ephA.publicKeyHex()), nonce + "00", sigB.toHex(), cloudPk));

        // 双方独立派生会话密钥应一致
        String skPile = crypto.deriveSessionKey(ephA.secretScalar(), Hex.decode(ephB.publicKeyHex()),
            Hex.decode(ephA.publicKeyHex()), Hex.decode(ephB.publicKeyHex()), pileId, cloudId, nonce);
        String skCloud = crypto.deriveSessionKey(ephB.secretScalar(), Hex.decode(ephA.publicKeyHex()),
            Hex.decode(ephA.publicKeyHex()), Hex.decode(ephB.publicKeyHex()), pileId, cloudId, nonce);
        assertEquals(skPile, skCloud);
        assertEquals(64, skPile.length());
    }
}
