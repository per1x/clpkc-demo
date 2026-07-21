package com.clpkc.kgc.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import org.junit.jupiter.api.Test;

/**
 * 隐式证书（ECQV/SM2）方案自洽性测试：KGC 颁发 → 组合 dA → 重构 PA → 双向 SM2 签名 → 会话密钥一致。
 */
class ClpkcCryptoTest {

    private final ClpkcCrypto crypto = new ClpkcCrypto();

    @Test
    void fullHandshakeIsConsistent() {
        BigInteger masterSecret = crypto.curve().randomScalar();
        String ppub = crypto.masterPublicHex(masterSecret);
        String pileId = "pile-001";
        String cloudId = "cloud-001";

        ClpkcCrypto.KeyMaterial pile = crypto.generateStaticKey();
        ClpkcCrypto.KeyMaterial cloud = crypto.generateStaticKey();
        ClpkcCrypto.PartialKey pilePk = crypto.issuePartialKey(masterSecret, pileId, pile.publicKeyHex());
        ClpkcCrypto.PartialKey cloudPk = crypto.issuePartialKey(masterSecret, cloudId, cloud.publicKeyHex());

        BigInteger pilePriv = crypto.composeFullPrivate(pile.secretScalar(), pilePk.encryptedPartialHex());
        BigInteger cloudPriv = crypto.composeFullPrivate(cloud.secretScalar(), cloudPk.encryptedPartialHex());

        String pilePub = crypto.reconstructFullPublicHex(pileId, pilePk.claimedPublicHex(), ppub);
        String cloudPub = crypto.reconstructFullPublicHex(cloudId, cloudPk.claimedPublicHex(), ppub);
        assertEquals(crypto.curve().xyHex(crypto.curve().basePointMul(pilePriv)), pilePub);
        assertEquals(crypto.curve().xyHex(crypto.curve().basePointMul(cloudPriv)), cloudPub);

        // nonce 固定 16 字节（协议规定）；原先误用 SM3 输出(32 字节)，新增的长度校验已将其暴露
        String nonce = Hex.encode(Arrays.copyOf(
            EcCurve.sm3("session-nonce".getBytes(StandardCharsets.UTF_8)), 16));

        // 桩=发起方B(R_B)、云=响应方A(R_A)
        ClpkcCrypto.KeyMaterial ephPile = crypto.generateStaticKey();   // R_B
        ClpkcCrypto.KeyMaterial ephCloud = crypto.generateStaticKey();  // R_A
        byte[] rB = Hex.decode(ephPile.publicKeyHex());
        byte[] rA = Hex.decode(ephCloud.publicKeyHex());

        // 桩(发起方)签 R_B ‖ ID_B ‖ W_B ‖ nonce
        String sigPile = crypto.signInitiator(rB, pileId, Hex.decode(pilePk.claimedPublicHex()), nonce, pilePriv);
        assertTrue(crypto.verifyInitiator(rB, pileId, Hex.decode(pilePk.claimedPublicHex()), nonce, sigPile, pilePub));

        // 云(响应方)签 R_A ‖ R_B ‖ ID_A ‖ W_A ‖ nonce
        String sigCloud = crypto.signResponder(rA, rB, cloudId, Hex.decode(cloudPk.claimedPublicHex()), nonce, cloudPriv);
        assertTrue(crypto.verifyResponder(rA, rB, cloudId, Hex.decode(cloudPk.claimedPublicHex()), nonce, sigCloud, cloudPub));

        // 篡改 nonce 应验签失败
        assertFalse(crypto.verifyResponder(rA, rB, cloudId, Hex.decode(cloudPk.claimedPublicHex()), nonce + "00", sigCloud, cloudPub));

        // SK = SM3(Sx ‖ R_A ‖ R_B ‖ ID_A ‖ ID_B ‖ nonce)
        String skPile = crypto.deriveSessionKey(ephPile.secretScalar(), ephCloud.publicKeyHex(),
            rA, rB, cloudId, pileId, nonce);
        String skCloud = crypto.deriveSessionKey(ephCloud.secretScalar(), ephPile.publicKeyHex(),
            rA, rB, cloudId, pileId, nonce);
        assertEquals(skPile, skCloud);
        assertEquals(64, skPile.length());
    }
}
