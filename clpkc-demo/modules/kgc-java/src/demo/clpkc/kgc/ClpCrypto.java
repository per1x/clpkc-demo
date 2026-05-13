package demo.clpkc.kgc;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

public final class ClpCrypto {
    private final Secp256r1 curve = new Secp256r1();
    private final BigInteger masterSecret;
    private final Secp256r1.Point masterPublic;

    public ClpCrypto() {
        // KGC 在系统启动时生成一次主密钥 s，对外只暴露主公钥 Ppub = sG。
        this.masterSecret = curve.randomScalar();
        this.masterPublic = curve.multiply(Secp256r1.G, masterSecret);
    }

    public BigInteger getMasterSecret() {
        return masterSecret;
    }

    public String getMasterPublicHex() {
        return Hexs.encode(curve.encode(masterPublic));
    }

    public BigInteger issuePartialPrivate(String id, String publicKeyHex) {
        // 这里实现 Demo 里的部分私钥公式：d_i = s * H1(ID_i || P_i) mod n。
        BigInteger h = h1(id, publicKeyHex);
        return masterSecret.multiply(h).mod(Secp256r1.N);
    }

    public BigInteger h1(String id, String publicKeyHex) {
        return hashToScalar(id.getBytes(StandardCharsets.UTF_8), Hexs.decode(publicKeyHex));
    }

    private BigInteger hashToScalar(byte[]... parts) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            for (byte[] part : parts) {
                md.update(part);
            }
            BigInteger v = new BigInteger(1, md.digest()).mod(Secp256r1.N);
            return v.equals(BigInteger.ZERO) ? BigInteger.ONE : v;
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
