package com.clpkc.cloud.socket;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.LinkedHashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.clpkc.cloud.crypto.ClpkcCrypto;
import com.clpkc.cloud.crypto.EcCurve;
import com.clpkc.cloud.crypto.Hex;
import com.clpkc.cloud.service.CloudIdentity;
import com.clpkc.cloud.service.PileDirectory;

/**
 * 处理单个充电桩长连接。<b>按报文类型分流两个阶段</b>：
 *
 * <ul>
 *   <li><b>第一阶段（provision，仅首次）</b>：桩发 {@code hmac} → <b>双向</b> HMAC-SM3 挑战应答
 *       （4 条报文，双方各出一个 16 字节随机挑战并互验）→ 转发 KGC 申请部分私钥。
 *       桩拿到后本地持久化，之后不再走此阶段。</li>
 *   <li><b>第二阶段（session，每次会话）</b>：桩直接发 {@code ka_request} → 云平台核对桩编号、
 *       用声明公钥重构 PA 验签 → 返回签名的 {@code ka_response} → 双方派生会话密钥。</li>
 * </ul>
 *
 * <p>两个阶段都由桩（主机）发起，云不下发 challenge。第一阶段用 random_A/random_B 双向挑战应答做
 * 身份互认；第二阶段的 nonce 由桩自生成（本次会话的新鲜随机数，绑定签名防重放），随桩的首报文发来，
 * 云只复用不重新生成。HMAC 认证与部分私钥申请只在第一阶段发生。</p>
 */
public final class PileSessionHandler implements Runnable {

    private static final Logger log = LoggerFactory.getLogger(PileSessionHandler.class);
    private static final int MAX_LINE_BYTES = 16 * 1024;
    /** 第一阶段挑战随机数字节数（random_A / random_B 各 16 字节，每次连接新鲜生成）。 */
    private static final int CHALLENGE_LEN = 16;
    private static final SecureRandom RANDOM = new SecureRandom();

    private final Socket socket;
    private final CloudIdentity identity;
    private final PileDirectory pileDirectory;
    private final int readTimeoutMs;

    public PileSessionHandler(Socket socket, CloudIdentity identity, PileDirectory pileDirectory, int readTimeoutMs) {
        this.socket = socket;
        this.identity = identity;
        this.pileDirectory = pileDirectory;
        this.readTimeoutMs = readTimeoutMs;
    }

    @Override
    public void run() {
        String peer = String.valueOf(socket.getRemoteSocketAddress());
        try (Socket s = socket) {
            s.setSoTimeout(readTimeoutMs);
            s.setTcpNoDelay(true);
            InputStream in = s.getInputStream();
            BufferedWriter writer = new BufferedWriter(
                new OutputStreamWriter(s.getOutputStream(), StandardCharsets.UTF_8));
            handle(in, writer, peer);
        } catch (Exception e) {
            log.warn("[Cloud][Socket] 连接 {} 处理结束/异常: {}", peer, e.getMessage());
        }
    }

    private void handle(InputStream in, BufferedWriter writer, String peer) throws IOException {
        // 桩（主机）发起：云不再下发 challenge，直接读桩的首报文并按类型分流。
        Map<String, String> msg = JsonCodec.parse(readLine(in));
        String type = msg.get("type");
        if ("hmac".equals(type)) {
            provision(in, writer, peer, msg);      // 第一阶段（桩自带 nonce）
        } else if ("ka_request".equals(type)) {
            session(writer, peer, msg);            // 第二阶段（桩发起，2 步）
        } else {
            log.warn("[Cloud][Socket] {} 未知首报文类型: {}", peer, type);
        }
    }

    /**
     * 第一阶段：<b>双向</b> HMAC-SM3 挑战应答 + 转发 KGC 申请部分私钥（仅首次）。
     *
     * <p>msg1 桩→云 {@code hmac(id, publicKey, randomB)}：桩以 random_B 挑战云；
     * msg2 云→桩 {@code hmac_challenge(mac=HMAC(PSK,random_B), randomA)}：云自证并反向挑战；
     * msg3 桩→云 {@code hmac_response(mac=HMAC(PSK,random_A))}：桩应答云的挑战；
     * msg4 云→桩 {@code auth_ok}：云验通过才放行后续密钥材料下发。
     * random_A / random_B 每次连接新鲜生成，任一侧校验失败立即中止。</p>
     */
    private void provision(InputStream in, BufferedWriter writer, String peer,
                           Map<String, String> hmacReq) throws IOException {
        String pileId = required(hmacReq, "id");
        byte[] randomB = Hex.decode(required(hmacReq, "randomB"));   // 桩对云的挑战

        // 云用 PSK 应答桩的挑战（自证身份），同时生成自己的挑战 random_A
        byte[] randomA = new byte[CHALLENGE_LEN];
        RANDOM.nextBytes(randomA);
        send(writer, ordered(
            "type", "hmac_challenge",
            "id", identity.id(),
            "mac", Hex.encode(identity.crypto().hmac(identity.sharedKey(), randomB)),
            "randomA", Hex.encode(randomA)));

        // 桩回 HMAC(PSK, random_A)，云校验；失败即中止，不下发任何密钥材料
        Map<String, String> authResp = JsonCodec.parse(readLine(in));
        if (!"hmac_response".equals(authResp.get("type"))) {
            log.warn("[Cloud][Socket] {} 第一阶段期待 hmac_response，实际: {}", peer, authResp.get("type"));
            send(writer, Map.of("type", "auth_fail"));
            return;
        }
        byte[] expected = identity.crypto().hmac(identity.sharedKey(), randomA);
        String macHex = authResp.get("mac");
        if (macHex == null || !MessageDigest.isEqual(expected, Hex.decode(macHex))) {
            log.warn("[Cloud][Socket] {} 桩端 HMAC 校验失败，拒绝。", peer);
            send(writer, Map.of("type", "auth_fail"));
            return;
        }
        log.info("[Cloud][Socket] {} 第一阶段双向 HMAC 认证通过，桩 id={}", peer, pileId);
        send(writer, ordered("type", "auth_ok", "id", identity.id()));

        Map<String, String> partialReq = JsonCodec.parse(readLine(in));
        Map<String, String> kgcResp = identity.forwardPartialKey(
            required(partialReq, "id"), required(partialReq, "publicKey"));
        send(writer, ordered(
            "type", "partial_key_response",
            "curve", kgcResp.get("curve"),
            "claimedPublic", kgcResp.get("claimedPublic"),
            "partialPrivate", kgcResp.get("partialPrivate"),
            "masterPublicKey", kgcResp.get("masterPublicKey")));
        log.info("[Cloud][Socket] {} 第一阶段完成，已下发声明公钥+部分私钥（桩本地持久化后走第二阶段）。", peer);
    }

    /** 第二阶段（桩发起，2 步）：验桩(发起方)签名 + 云(响应方)签名回应 + 派生会话密钥。 */
    private void session(BufferedWriter writer, String peer, Map<String, String> kaReq) throws IOException {
        ClpkcCrypto crypto = identity.crypto();
        String pileId = required(kaReq, "id");                       // ID_B

        // 桩编号核对（对接云平台既有编号系统，见 PileDirectory）
        if (!pileDirectory.isAuthorized(pileId)) {
            log.warn("[Cloud][Socket] {} 桩编号未授权: {}", peer, pileId);
            send(writer, Map.of("type", "ka_fail"));
            return;
        }

        String nonceHex = required(kaReq, "nonce");                  // 桩生成的 nonce
        String rBHex = required(kaReq, "rB");                        // R_B（桩临时公钥）
        String wBHex = required(kaReq, "claimedPublic");            // W_B（桩自己的声明公钥）
        String pileFullPublic = crypto.reconstructFullPublicHex(
            pileId, wBHex, identity.masterPublicHex());
        // 验桩(发起方)签名 transcript = R_B ‖ ID_B ‖ W_B ‖ nonce
        boolean ok = crypto.verifyInitiator(Hex.decode(rBHex), pileId, Hex.decode(wBHex),
            nonceHex, required(kaReq, "sig"), pileFullPublic);
        if (!ok) {
            log.warn("[Cloud][Socket] {} 桩端 KA 签名校验失败。", peer);
            send(writer, Map.of("type", "ka_fail"));
            return;
        }

        // 云(响应方)生成临时公钥 R_A，签 transcript = R_A ‖ R_B ‖ ID_A ‖ W_A ‖ nonce
        ClpkcCrypto.KeyMaterial cloudEph = crypto.generateStaticKey();  // (r_A, R_A)
        String rAHex = cloudEph.publicKeyHex();
        String sig = crypto.signResponder(Hex.decode(rAHex), Hex.decode(rBHex),
            identity.id(), Hex.decode(identity.claimedPublicHex()), nonceHex, identity.fullPrivate());
        send(writer, ordered(
            "type", "ka_response",
            "id", identity.id(),
            "claimedPublic", identity.claimedPublicHex(),
            "rA", rAHex,
            "sig", sig));

        // SK = SM3(Sx ‖ R_A ‖ R_B ‖ ID_A ‖ ID_B ‖ nonce)
        String sessionKey = crypto.deriveSessionKey(cloudEph.secretScalar(),
            rBHex, Hex.decode(rAHex), Hex.decode(rBHex),
            identity.id(), pileId, nonceHex);
        if (sessionKey.length() != 64) {
            throw new IllegalStateException("session key derivation failed");
        }
        String fingerprint = Hex.encode(EcCurve.sm3(
            sessionKey.getBytes(StandardCharsets.UTF_8))).substring(0, 16);
        log.info("[Cloud] 第二阶段与桩 {} 会话密钥协商完成（指纹 SM3(SK)[0:16]={}，密钥不落日志）。",
            pileId, fingerprint);
    }

    private void send(BufferedWriter writer, Map<String, String> body) throws IOException {
        writer.write(JsonCodec.stringify(body));
        writer.write('\n');
        writer.flush();
    }

    private static Map<String, String> ordered(String... kv) {
        Map<String, String> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) {
            m.put(kv[i], kv[i + 1]);
        }
        return m;
    }

    private static String required(Map<String, String> map, String key) {
        String v = map.get(key);
        if (v == null || v.isBlank()) {
            throw new IllegalArgumentException("缺少字段: " + key);
        }
        return v;
    }

    /** 读取一行（'\n' 结尾），限制最大字节数以防内存耗尽。 */
    private String readLine(InputStream in) throws IOException {
        java.io.ByteArrayOutputStream buf = new java.io.ByteArrayOutputStream(256);
        int b;
        while ((b = in.read()) != -1) {
            if (b == '\n') {
                return buf.toString(StandardCharsets.UTF_8);
            }
            if (b != '\r') {
                buf.write(b);
            }
            if (buf.size() > MAX_LINE_BYTES) {
                throw new IOException("line exceeds max length " + MAX_LINE_BYTES);
            }
        }
        throw new IOException("connection closed by peer");
    }
}
