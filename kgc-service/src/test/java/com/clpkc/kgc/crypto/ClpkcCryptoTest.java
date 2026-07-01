package com.clpkc.kgc.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

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

        String nonce = Hex.encode(EcCurve.sm3("session-nonce".getBytes(StandardCharsets.UTF_8)));

        ClpkcCrypto.KeyMaterial ephA = crypto.generateStaticKey();
        String sigA = crypto.sign(Hex.decode(ephA.publicKeyHex()), pileId,
            Hex.decode(cloudPk.claimedPublicHex()), nonce, pilePriv);
        assertTrue(crypto.verify(Hex.decode(ephA.publicKeyHex()), pileId,
            Hex.decode(cloudPk.claimedPublicHex()), nonce, sigA, pilePub));

        ClpkcCrypto.KeyMaterial ephB = crypto.generateStaticKey();
        String sigB = crypto.sign(Hex.decode(ephB.publicKeyHex()), cloudId,
            Hex.decode(ephA.publicKeyHex()), nonce, cloudPriv);
        assertTrue(crypto.verify(Hex.decode(ephB.publicKeyHex()), cloudId,
            Hex.decode(ephA.publicKeyHex()), nonce, sigB, cloudPub));

        assertFalse(crypto.verify(Hex.decode(ephB.publicKeyHex()), cloudId,
            Hex.decode(ephA.publicKeyHex()), nonce + "00", sigB, cloudPub));

        String skPile = crypto.deriveSessionKey(ephA.secretScalar(), ephB.publicKeyHex(),
            Hex.decode(ephA.publicKeyHex()), Hex.decode(ephB.publicKeyHex()), pileId, cloudId, nonce);
        String skCloud = crypto.deriveSessionKey(ephB.secretScalar(), ephA.publicKeyHex(),
            Hex.decode(ephA.publicKeyHex()), Hex.decode(ephB.publicKeyHex()), pileId, cloudId, nonce);
        assertEquals(skPile, skCloud);
        assertEquals(64, skPile.length());
    }
}
