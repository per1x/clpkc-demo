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

import com.clpkc.cloud.service.CloudIdentity;
import com.clpkc.core.ClpkcCrypto;
import com.clpkc.core.util.Hex;

/**
 * 处理单个充电桩长连接的握手流程（无时间戳，仅用 nonce 防重放）。
 *
 * <p>四步：① HMAC 挑战-响应认证 → ② 转发部分私钥申请到 KGC → ③ 验桩端签名的 KA 请求
 * → ④ 返回云端签名的 KA 响应并派生会话密钥。</p>
 *
 * <p>生产化要点：设置读超时、限制单行最大长度（防内存耗尽），JSON 用 Jackson 解析，
 * 敏感值（会话密钥、私钥）不落日志。</p>
 */
public final class PileSessionHandler implements Runnable {

    private static final Logger log = LoggerFactory.getLogger(PileSessionHandler.class);
    private static final int MAX_LINE_BYTES = 16 * 1024;
    private static final SecureRandom RANDOM = new SecureRandom();

    private final Socket socket;
    private final CloudIdentity identity;
    private final int readTimeoutMs;

    public PileSessionHandler(Socket socket, CloudIdentity identity, int readTimeoutMs) {
        this.socket = socket;
        this.identity = identity;
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
            handshake(in, writer, peer);
        } catch (Exception e) {
            log.warn("[Cloud][Socket] 连接 {} 处理结束/异常: {}", peer, e.getMessage());
        }
    }

    private void handshake(InputStream in, BufferedWriter writer, String peer) throws IOException {
        ClpkcCrypto crypto = identity.crypto();

        // ① 下发挑战 nonce
        byte[] nonce = new byte[16];
        RANDOM.nextBytes(nonce);
        String nonceHex = Hex.encode(nonce);
        send(writer, Map.of("type", "challenge", "nonce", nonceHex));

        // ② HMAC 校验
        Map<String, String> hmacReq = JsonCodec.parse(readLine(in));
        byte[] expected = crypto.hmac(identity.sharedKey(), nonce);
        String macHex = hmacReq.get("mac");
        if (macHex == null || !MessageDigest.isEqual(expected, Hex.decode(macHex))) {
            log.warn("[Cloud][Socket] {} HMAC 校验失败，拒绝。", peer);
            send(writer, Map.of("type", "auth_fail"));
            return;
        }
        String pileId = required(hmacReq, "id");
        log.info("[Cloud][Socket] {} HMAC 认证通过，桩 id={}", peer, pileId);
        send(writer, ordered(
            "type", "auth_ok",
            "id", identity.id(),
            "publicKey", identity.staticPublicHex(),
            "derivedPublic", identity.derivedPublicHex()));

        // ③ 转发部分私钥申请到 KGC
        Map<String, String> partialReq = JsonCodec.parse(readLine(in));
        Map<String, String> kgcResp = identity.forwardPartialKey(
            required(partialReq, "id"), required(partialReq, "publicKey"));
        send(writer, ordered(
            "type", "partial_key_response",
            "curve", kgcResp.get("curve"),
            "partialPrivate", kgcResp.get("partialPrivate"),
            "masterPublicKey", kgcResp.get("masterPublicKey")));

        // ④ 验签 KA 请求
        Map<String, String> kaReq = JsonCodec.parse(readLine(in));
        String raHex = required(kaReq, "ra");
        String pileFullPublic = crypto.deriveFullPublic(
            required(kaReq, "publicKey"), required(kaReq, "derivedPublic"));
        boolean ok = crypto.verify(Hex.decode(raHex), required(kaReq, "id"),
            Hex.decode(identity.staticPublicHex()), nonceHex, required(kaReq, "sig"), pileFullPublic);
        if (!ok) {
            log.warn("[Cloud][Socket] {} 桩端 KA 签名校验失败。", peer);
            send(writer, Map.of("type", "ka_fail"));
            return;
        }

        // ⑤ 云端临时密钥 + 签名响应
        ClpkcCrypto.KeyMaterial ephemeral = crypto.generateStaticKey();
        ClpkcCrypto.Signature sig = crypto.sign(Hex.decode(ephemeral.publicKeyHex()),
            identity.id(), Hex.decode(raHex), nonceHex, identity.fullPrivate());
        send(writer, ordered(
            "type", "ka_response",
            "id", identity.id(),
            "publicKey", identity.staticPublicHex(),
            "derivedPublic", identity.derivedPublicHex(),
            "rb", ephemeral.publicKeyHex(),
            "sig", sig.toHex()));

        // ⑥ 派生会话密钥（不落日志）
        String sessionKey = crypto.deriveSessionKey(ephemeral.secretScalar(),
            Hex.decode(raHex), Hex.decode(raHex), Hex.decode(ephemeral.publicKeyHex()),
            required(kaReq, "id"), identity.id(), nonceHex);
        if (sessionKey.length() != 64) {
            throw new IllegalStateException("session key derivation failed");
        }
        String fingerprint = Hex.encode(com.clpkc.core.EcCurve.sha256(
            sessionKey.getBytes(StandardCharsets.UTF_8))).substring(0, 16);
        log.info("[Cloud] 与桩 {} 会话密钥协商完成（指纹 SHA256(SK)[0:16]={}，密钥不落日志）。",
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
