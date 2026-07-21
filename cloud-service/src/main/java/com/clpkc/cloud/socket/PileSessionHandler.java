package com.clpkc.cloud.socket;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
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
            OutputStream out = s.getOutputStream();
            Frame first = Frame.read(in);           // 桩（主机）发起，读首帧按类型分流
            if (first.type == Frame.TYPE_P1_UP) {
                provision(in, out, peer, first);    // 第一阶段（0x39/0x3A）
            } else if (first.type == Frame.TYPE_P2_UP) {
                session(in, out, peer, first);      // 第二阶段（0x3B/0x3C）
            } else {
                log.warn("[Cloud][Socket] {} 未知首帧类型: 0x{}", peer, Integer.toHexString(first.type));
            }
        } catch (Exception e) {
            log.warn("[Cloud][Socket] 连接 {} 处理结束/异常: {}", peer, e.getMessage());
        }
    }

    /**
     * 第一阶段：<b>双向</b> HMAC-SM3 挑战应答 + 转发 KGC 申请部分私钥（二进制帧 0x39/0x3A）。
     *
     * <p>msg1 桩→云 hmac_req(ID_B, UA, randomB)；msg2 云→桩 hmac_challenge(ID_A, mac_B, randomA)；
     * msg3 桩→云 hmac_response(mac_A)；msg4 云→桩 auth_result(result)；
     * msg5 桩→云 pk_request(ID_B, UA)；msg6 云→桩 pk_response(WA, partialPrivate, Ppub)。
     * random_A/random_B 每次连接新鲜生成，任一侧校验失败立即回 result=FAIL 并中止。</p>
     */
    private void provision(InputStream in, OutputStream out, String peer, Frame msg1) throws IOException {
        int seq = 1;
        // msg1 (0x39/0x11 hmac_req): STEP ‖ ID_B(32) ‖ UA(64) ‖ randomB(16)
        Frame.Reader r1 = new Frame.Reader(msg1.payload);
        if (r1.u8() != Frame.STEP_1_REQ) {
            log.warn("[Cloud][Socket] {} 第一阶段首帧 STEP 非法。", peer);
            return;
        }
        String pileId = idFrom32(r1.take(32));
        r1.take(64);                                  // UA（此处不用，见 pk_request）
        byte[] randomB = r1.take(16);                 // 桩对云的挑战
        byte[] host = Frame.bcd7FromId(pileId);

        // msg2 (0x3A/0x12 hmac_challenge): STEP ‖ ID_A(32) ‖ mac_B(32) ‖ randomA(16)
        byte[] randomA = new byte[CHALLENGE_LEN];
        RANDOM.nextBytes(randomA);
        byte[] macB = identity.crypto().hmac(identity.sharedKey(), randomB);   // 云自证
        byte[] p2 = new Frame.Writer().step(Frame.STEP_1_RESP)
            .bytes(id32(identity.id())).bytes(macB).bytes(randomA).toArray();
        Frame.write(out, Frame.encode(Frame.TYPE_P1_DOWN, seq++, host, p2));

        // msg3 (0x39/0x21 hmac_response): STEP ‖ mac_A(32)，云校验；失败即中止，不下发密钥材料
        Frame f3 = Frame.read(in);
        Frame.Reader r3 = new Frame.Reader(f3.payload);
        if (f3.type != Frame.TYPE_P1_UP || r3.u8() != Frame.STEP_2_REQ) {
            log.warn("[Cloud][Socket] {} 第一阶段期待 hmac_response(0x39/0x21)。", peer);
            sendAuthResult(out, host, seq, Frame.RESULT_FAIL);
            return;
        }
        byte[] macA = r3.take(32);
        byte[] expected = identity.crypto().hmac(identity.sharedKey(), randomA);
        if (!MessageDigest.isEqual(expected, macA)) {
            log.warn("[Cloud][Socket] {} 桩端 HMAC 校验失败，拒绝。", peer);
            sendAuthResult(out, host, seq, Frame.RESULT_FAIL);
            return;
        }
        // msg4 (0x3A/0x22 auth_result): STEP ‖ result(1) ‖ ID_A(32)
        sendAuthResult(out, host, seq++, Frame.RESULT_OK);
        log.info("[Cloud][Socket] {} 第一阶段双向 HMAC 认证通过，桩 id={}", peer, pileId);

        // msg5 (0x39/0x31 pk_request): STEP ‖ ID_B(32) ‖ UA(64)
        Frame f5 = Frame.read(in);
        Frame.Reader r5 = new Frame.Reader(f5.payload);
        if (f5.type != Frame.TYPE_P1_UP || r5.u8() != Frame.STEP_3_REQ) {
            log.warn("[Cloud][Socket] {} 第一阶段期待 pk_request(0x39/0x31)。", peer);
            return;
        }
        String reqId = idFrom32(r5.take(32));
        String reqUa = Hex.encode(r5.take(64));
        Map<String, String> kgcResp = identity.forwardPartialKey(reqId, reqUa);   // 云↔KGC 仍 JSON/HTTP

        // msg6 (0x3A/0x32 pk_response): STEP ‖ WA(64) ‖ partialPrivate(129) ‖ Ppub(64)
        byte[] p6 = new Frame.Writer().step(Frame.STEP_3_RESP)
            .bytes(Hex.decode(kgcResp.get("claimedPublic")))
            .bytes(Hex.decode(kgcResp.get("partialPrivate")))
            .bytes(Hex.decode(kgcResp.get("masterPublicKey"))).toArray();
        Frame.write(out, Frame.encode(Frame.TYPE_P1_DOWN, seq, host, p6));
        log.info("[Cloud][Socket] {} 第一阶段完成，已下发声明公钥+部分私钥。", peer);
    }

    private void sendAuthResult(OutputStream out, byte[] host, int seq, int result) throws IOException {
        byte[] p = new Frame.Writer().step(Frame.STEP_2_RESP).u8(result).bytes(id32(identity.id())).toArray();
        Frame.write(out, Frame.encode(Frame.TYPE_P1_DOWN, seq, host, p));
    }

    /**
     * 第二阶段：验桩签名 + 云签名回应 + 双向回执 + 派生会话密钥（二进制帧 0x3B/0x3C）。
     *
     * <p>msg1 桩→云 ka_request；msg2 云→桩 ka_response(含云对桩签名的验签结果)；
     * msg3 桩→云 ka_confirm(桩对云签名的验签结果 + 是否收到)；msg4 云→桩 ka_ack(已收到)。</p>
     */
    private void session(InputStream in, OutputStream out, String peer, Frame msg1) throws IOException {
        ClpkcCrypto crypto = identity.crypto();
        int seq = 1;
        // msg1 (0x3B/0x11 ka_request): STEP ‖ UUID(32) ‖ CP56(7) ‖ ID_B(32) ‖ WB(64) ‖ rB(64) ‖ nonce(16) ‖ sig_B(64)
        Frame.Reader r = new Frame.Reader(msg1.payload);
        if (r.u8() != Frame.STEP_1_REQ) {
            log.warn("[Cloud][Socket] {} 第二阶段首帧 STEP 非法。", peer);
            return;
        }
        byte[] uuid = r.take(32);
        r.take(7);                                     // CP56Time2a（传输元数据）
        String pileId = idFrom32(r.take(32));          // ID_B
        byte[] host = Frame.bcd7FromId(pileId);
        String wBHex = Hex.encode(r.take(64));         // W_B
        byte[] rB = r.take(64);                        // R_B
        String nonceHex = Hex.encode(r.take(16));      // nonce（16 字节 → hex 供密码学层）
        byte[] sigB = r.take(64);                      // sig_B

        // 桩编号核对（对接云平台既有编号系统，见 PileDirectory）
        if (!pileDirectory.isAuthorized(pileId)) {
            log.warn("[Cloud][Socket] {} 桩编号未授权: {}", peer, pileId);
            sendKaResponseFail(out, host, seq, uuid);
            return;
        }
        String pileFullPublic = crypto.reconstructFullPublicHex(pileId, wBHex, identity.masterPublicHex());
        // 验桩(发起方)签名 transcript = R_B ‖ ID_B ‖ W_B ‖ nonce
        boolean pileOk = crypto.verifyInitiator(rB, pileId, Hex.decode(wBHex),
            nonceHex, Hex.encode(sigB), pileFullPublic);
        if (!pileOk) {
            log.warn("[Cloud][Socket] {} 桩端 KA 签名校验失败。", peer);
            sendKaResponseFail(out, host, seq, uuid);
            return;
        }

        // 云(响应方)生成临时公钥 R_A，签 transcript = R_A ‖ R_B ‖ ID_A ‖ W_A ‖ nonce
        ClpkcCrypto.KeyMaterial cloudEph = crypto.generateStaticKey();  // (r_A, R_A)
        String rAHex = cloudEph.publicKeyHex();
        String sig = crypto.signResponder(Hex.decode(rAHex), rB, identity.id(),
            Hex.decode(identity.claimedPublicHex()), nonceHex, identity.fullPrivate());
        // msg2 (0x3C/0x12 ka_response): STEP ‖ UUID ‖ CP56 ‖ result(OK) ‖ ID_A(32) ‖ WA(64) ‖ rA(64) ‖ sig_A(64)
        byte[] p2 = new Frame.Writer().step(Frame.STEP_1_RESP)
            .bytes(uuid).bytes(Frame.cp56Now()).u8(Frame.RESULT_OK)
            .bytes(id32(identity.id())).bytes(Hex.decode(identity.claimedPublicHex()))
            .bytes(Hex.decode(rAHex)).bytes(Hex.decode(sig)).toArray();
        Frame.write(out, Frame.encode(Frame.TYPE_P2_DOWN, seq++, host, p2));

        // SK = SM3(Sx ‖ R_A ‖ R_B ‖ ID_A ‖ ID_B ‖ nonce)
        String sessionKey = crypto.deriveSessionKey(cloudEph.secretScalar(),
            Hex.encode(rB), Hex.decode(rAHex), rB, identity.id(), pileId, nonceHex);
        if (sessionKey.length() != 64) {
            throw new IllegalStateException("session key derivation failed");
        }

        // msg3 (0x3B/0x21 ka_confirm): STEP ‖ UUID ‖ CP56 ‖ result(桩验云签名) ‖ received(是否收到)
        Frame f3 = Frame.read(in);
        Frame.Reader r3 = new Frame.Reader(f3.payload);
        if (f3.type != Frame.TYPE_P2_UP || r3.u8() != Frame.STEP_2_REQ) {
            log.warn("[Cloud][Socket] {} 第二阶段未收到桩回执(0x3B/0x21)。", peer);
            return;
        }
        r3.take(32);                                   // UUID
        r3.take(7);                                    // CP56
        int pileVerify = r3.u8();
        int received = r3.u8();
        // msg4 (0x3C/0x22 ka_ack): STEP ‖ UUID ‖ CP56 ‖ received(已收到)
        byte[] p4 = new Frame.Writer().step(Frame.STEP_2_RESP)
            .bytes(uuid).bytes(Frame.cp56Now()).u8(Frame.RECEIVED_YES).toArray();
        Frame.write(out, Frame.encode(Frame.TYPE_P2_DOWN, seq, host, p4));

        String fingerprint = Hex.encode(EcCurve.sm3(
            sessionKey.getBytes(StandardCharsets.UTF_8))).substring(0, 16);
        log.info("[Cloud] 第二阶段与桩 {} 会话密钥协商完成（指纹 SM3(SK)[0:16]={}，桩验签={}，桩已收={}，密钥不落日志）。",
            pileId, fingerprint,
            pileVerify == Frame.RESULT_OK ? "通过" : "失败",
            received == Frame.RECEIVED_YES ? "是" : "否");
    }

    /** 验签/授权失败时回 ka_response(result=FAIL)，其余字段填 0；桩见 result!=OK 即中止。 */
    private void sendKaResponseFail(OutputStream out, byte[] host, int seq, byte[] uuid) throws IOException {
        byte[] p = new Frame.Writer().step(Frame.STEP_1_RESP)
            .bytes(uuid).bytes(Frame.cp56Now()).u8(Frame.RESULT_FAIL)
            .bytes(id32(identity.id())).bytes(new byte[64]).bytes(new byte[64]).bytes(new byte[64]).toArray();
        Frame.write(out, Frame.encode(Frame.TYPE_P2_DOWN, seq, host, p));
    }

    private static byte[] id32(String id) {
        byte[] raw = id.getBytes(StandardCharsets.UTF_8);
        byte[] out = new byte[32];
        System.arraycopy(raw, 0, out, 0, Math.min(raw.length, 32));
        return out;
    }

    private static String idFrom32(byte[] b) {
        int n = b.length;
        while (n > 0 && b[n - 1] == 0) {
            n--;
        }
        return new String(b, 0, n, StandardCharsets.UTF_8);
    }
}
