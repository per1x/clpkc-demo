import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

import com.clpkc.cloud.crypto.ClpkcCrypto;
import com.clpkc.cloud.crypto.EcCurve;
import com.clpkc.cloud.crypto.Hex;

/**
 * KAT 交叉验证工具：用 **Java 云端(cloud-service)** 的 ClpkcCrypto 对与 C++ SDK 相同的
 * 固定输入算一遍，输出 name=value，用于和 pile-sdk/selftest.cpp 的期望值逐行比对。
 *
 * 编译/运行见 pile-sdk/kat.md「如何复现交叉验证」。
 * 可选参数 argv[0] = C++ SDK 产出的 initiator 签名(裸 r‖s hex)，传入则由 Java 验签，
 * 形成 C++签→Java验 的反向交叉验证。
 */
public final class KatGen {

    // ---- 固定输入（与 selftest.cpp / kat.md 完全一致）----
    static final String MS_HEX    = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    static final String UA_HEX    = "1122334455667788990011223344556677889900112233445566778899001122";
    static final String CLOUD_UA  = "2233445566778899001122334455667788990011223344556677889900112233";
    static final String EPH_B_HEX = "3344556677889900112233445566778899001122334455667788990011223344";
    static final String EPH_A_HEX = "4455667788990011223344556677889900112233445566778899001122334455";
    static final String NONCE_HEX = "0102030405060708090a0b0c0d0e0f10";
    static final String PSK_HEX   = "00112233445566778899aabbccddeeff";
    static final String ID_PILE   = "pile-001";
    static final String ID_CLOUD  = "cloud-001";

    // 冻结进 kat.md 的值（issuePartialKey 含随机 w，故固定下来供反向验签复现）
    static final String FROZEN_W_PILE =
        "8b77aba1b8eb7a0df8131058f70a530b380e45e97237f10f7d0a6ea1be18e158"
        + "569211790e4e77e087fdf412cca00c4ffddbffdcb987beac2236b72500fccf7c";
    static final String FROZEN_PK_PILE =
        "1761f4ec4d1d2edb7d04fc7a187e58b9351db8ee0e79cf6e6494596443da5df9"
        + "897dc95ef97269cd9061ed27d8f6a8088d9eb24b65fcea6d4f42eee98d8c9ae3";

    public static void main(String[] args) {
        ClpkcCrypto crypto = new ClpkcCrypto();
        EcCurve curve = crypto.curve();

        BigInteger ms = new BigInteger(MS_HEX, 16);
        BigInteger ua = new BigInteger(UA_HEX, 16);
        BigInteger cloudUa = new BigInteger(CLOUD_UA, 16);
        BigInteger ephB = new BigInteger(EPH_B_HEX, 16);
        BigInteger ephA = new BigInteger(EPH_A_HEX, 16);

        String ppub = crypto.masterPublicHex(ms);
        String uaPubPile = curve.xyHex(curve.basePointMul(ua));
        String uaPubCloud = curve.xyHex(curve.basePointMul(cloudUa));
        String rB = curve.xyHex(curve.basePointMul(ephB));
        String rA = curve.xyHex(curve.basePointMul(ephA));

        p("ppub", ppub);
        p("ua_pub_pile", uaPubPile);
        p("ua_pub_cloud", uaPubCloud);
        p("rB", rB);
        p("rA", rA);

        // 隐式证书颁发（含随机 w → W/密文每次不同，需冻结进 KAT）
        ClpkcCrypto.PartialKey pilePk = crypto.issuePartialKey(ms, ID_PILE, uaPubPile);
        ClpkcCrypto.PartialKey cloudPk = crypto.issuePartialKey(ms, ID_CLOUD, uaPubCloud);
        p("W_pile", pilePk.claimedPublicHex());
        p("cipher_pile", pilePk.encryptedPartialHex());
        p("W_cloud", cloudPk.claimedPublicHex());
        p("cipher_cloud", cloudPk.encryptedPartialHex());

        // 确定性输出
        p("t_pile", Hex.encode(crypto.sm2Decrypt(pilePk.encryptedPartialHex(), ua)));
        BigInteger skPile = crypto.composeFullPrivate(ua, pilePk.encryptedPartialHex());
        BigInteger skCloud = crypto.composeFullPrivate(cloudUa, cloudPk.encryptedPartialHex());
        p("sk_pile", Hex.encode(curve.toFixed(skPile, EcCurve.SCALAR_LEN)));
        p("sk_cloud", Hex.encode(curve.toFixed(skCloud, EcCurve.SCALAR_LEN)));
        p("pk_pile", crypto.reconstructFullPublicHex(ID_PILE, pilePk.claimedPublicHex(), ppub));
        p("pk_cloud", crypto.reconstructFullPublicHex(ID_CLOUD, cloudPk.claimedPublicHex(), ppub));

        // HMAC-SM3 / SM3
        p("hmac", Hex.encode(crypto.hmac(Hex.decode(PSK_HEX), Hex.decode(NONCE_HEX))));
        p("sm3_abc", Hex.encode(EcCurve.sm3("abc".getBytes(StandardCharsets.UTF_8))));

        // 会话密钥（两端各算一遍应相等）
        String skSessPile = crypto.deriveSessionKey(ephB, rA, Hex.decode(rA), Hex.decode(rB),
            ID_CLOUD, ID_PILE, NONCE_HEX);
        String skSessCloud = crypto.deriveSessionKey(ephA, rB, Hex.decode(rA), Hex.decode(rB),
            ID_CLOUD, ID_PILE, NONCE_HEX);
        p("session_key", skSessPile);
        p("session_key_match", String.valueOf(skSessPile.equals(skSessCloud)));
        p("sm4_key", skSessPile.substring(0, 32));

        // 云(响应方)签名 —— 冻结进 KAT，供 C++ verify_responder 验证
        String sigResp = crypto.signResponder(Hex.decode(rA), Hex.decode(rB), ID_CLOUD,
            Hex.decode(cloudPk.claimedPublicHex()), NONCE_HEX, skCloud);
        p("sig_responder", sigResp);
        p("sig_responder_selfcheck", String.valueOf(crypto.verifyResponder(Hex.decode(rA),
            Hex.decode(rB), ID_CLOUD, Hex.decode(cloudPk.claimedPublicHex()), NONCE_HEX,
            sigResp, crypto.reconstructFullPublicHex(ID_CLOUD, cloudPk.claimedPublicHex(), ppub))));

        // 反向交叉验证：Java 验 C++ SDK 产出的 initiator 签名。
        // 必须用 **冻结进 KAT 的 W_pile**（issuePartialKey 含随机 w，每次运行不同）。
        if (args.length > 0 && args[0].length() == 128) {
            String pkPileFrozen = crypto.reconstructFullPublicHex(ID_PILE, FROZEN_W_PILE, ppub);
            boolean ok = crypto.verifyInitiator(Hex.decode(rB), ID_PILE,
                Hex.decode(FROZEN_W_PILE), NONCE_HEX, args[0], pkPileFrozen);
            p("frozen_pk_pile_matches_kat", String.valueOf(pkPileFrozen.equals(FROZEN_PK_PILE)));
            p("java_verifies_cpp_initiator_sig", String.valueOf(ok));
        }
    }

    private static void p(String k, String v) {
        System.out.println(k + "=" + v);
    }
}
