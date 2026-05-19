package demo.clpkc.cloud;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

public final class CloudPlatformServer {
    public static void main(String[] args) throws Exception {
        String cloudId = System.getProperty("cloud.id", "cloud-001");
        String kgcUrl = System.getProperty("kgc.url", "https://localhost:8443/api/partial-key");
        String kgcPem = System.getProperty("kgc.cert", "../kgc-java/certs/kgc-cert.pem");
        int port = Integer.parseInt(System.getProperty("cloud.port", "9000"));
        byte[] sharedKey = Hexs.decode(System.getProperty("shared.key",
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"));

        ClpCrypto crypto = new ClpCrypto();
        ClpCrypto.KeyMaterial cloudStatic = crypto.generateStaticKey();
        HttpsJsonClient kgcClient = new HttpsJsonClient(java.nio.file.Path.of(kgcPem));

        System.out.println("[Cloud] 启动中，先为自己生成静态密钥对并向 KGC 申请部分私钥。");
        Map<String, String> ownReq = new LinkedHashMap<>();
        ownReq.put("id", cloudId);
        ownReq.put("publicKey", cloudStatic.publicKeyHex());
        Map<String, String> ownResp = kgcClient.post(kgcUrl, ownReq);
        ClpCrypto.FullKey cloudKey = crypto.composeFullKey(cloudStatic.secretScalar(), ownResp.get("partialPrivate"));
        BigInteger cloudFullPrivate = cloudKey.privateScalar();
        String cloudDerivedPublic = cloudKey.derivedPublicHex();
        String cloudFullPublic = crypto.deriveFullPublic(cloudStatic.publicKeyHex(), cloudDerivedPublic);
        System.out.println("[Cloud] 静态公钥 P_i = " + cloudStatic.publicKeyHex());
        System.out.println("[Cloud] 派生公钥 Y_i = " + cloudDerivedPublic);
        System.out.println("[Cloud] 完整公钥 PK_i = " + cloudFullPublic);

        try (ServerSocket serverSocket = new ServerSocket(port)) {
            System.out.println("[Cloud] TCP Socket 服务已启动: tcp://0.0.0.0:" + port);
            System.out.println("[Cloud] 对外公布的静态公钥 = " + cloudStatic.publicKeyHex());
            while (true) {
                try (Socket socket = serverSocket.accept()) {
                    System.out.println("[Cloud] 收到新的充电桩连接: " + socket.getRemoteSocketAddress());
                    handleConnection(socket, crypto, kgcClient, kgcUrl, sharedKey, cloudId,
                        cloudStatic.publicKeyHex(), cloudDerivedPublic,
                        cloudFullPrivate, cloudFullPublic);
                }
            }
        }
    }

    private static void handleConnection(Socket socket, ClpCrypto crypto, HttpsJsonClient kgcClient, String kgcUrl, byte[] sharedKey,
                                         String cloudId, String cloudPublicKey, String cloudDerivedPublic,
                                         BigInteger cloudFullPrivate, String cloudFullPublic) throws Exception {
        BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
        BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8));

        // 第一步：基于预共享密钥做 HMAC challenge-response，未通过不允许继续。
        byte[] nonce = new byte[16];
        new java.security.SecureRandom().nextBytes(nonce);
        System.out.println("[Cloud][Socket] 向充电桩发送挑战随机数 nonce = " + Hexs.encode(nonce));
        send(writer, Map.of("type", "challenge", "nonce", Hexs.encode(nonce)));

        Map<String, String> hmacReq = SimpleJson.parse(reader.readLine());
        System.out.println("[Cloud][Socket] 收到 HMAC 认证报文: " + hmacReq);
        byte[] expectedMac = crypto.hmac(sharedKey, nonce);
        if (!Hexs.encode(expectedMac).equals(hmacReq.get("mac"))) {
            System.out.println("[Cloud][Socket] HMAC 校验失败，拒绝后续访问。");
            send(writer, Map.of("type", "auth_fail"));
            return;
        }
        System.out.println("[Cloud][Socket] HMAC 校验通过，允许继续申请部分私钥和密钥协商。");
        send(writer, Map.of("type", "auth_ok", "id", cloudId, "publicKey", cloudPublicKey, "derivedPublic", cloudDerivedPublic));

        // 第二步：把充电桩的部分私钥申请通过 HTTPS 转发给 KGC。
        Map<String, String> partialReq = SimpleJson.parse(reader.readLine());
        System.out.println("[Cloud][Socket] 收到充电桩部分私钥申请: " + partialReq);
        Map<String, String> forwardReq = new LinkedHashMap<>();
        forwardReq.put("id", partialReq.get("id"));
        forwardReq.put("publicKey", partialReq.get("publicKey"));
        Map<String, String> partialResp = kgcClient.post(kgcUrl, forwardReq);
        Map<String, String> partialReply = new LinkedHashMap<>();
        partialReply.put("type", "partial_key_response");
        partialReply.put("curve", partialResp.get("curve"));
        partialReply.put("partialPrivate", partialResp.get("partialPrivate"));
        partialReply.put("masterPublicKey", partialResp.get("masterPublicKey"));
        System.out.println("[Cloud][Socket] 已将 KGC 返回的部分私钥透传给充电桩。");
        send(writer, partialReply);

        // 第三步：接收充电桩带签名的 ECDH 发起报文，并用其完整公钥验签。
        Map<String, String> kaReq = SimpleJson.parse(reader.readLine());
        System.out.println("[Cloud][Socket] 收到密钥协商请求: " + kaReq);
        String pileId = kaReq.get("id");
        String pilePublicKey = kaReq.get("publicKey");
        String pileDerivedPublic = kaReq.get("derivedPublic");
        String pileFullPublic = crypto.deriveFullPublic(pilePublicKey, pileDerivedPublic);
        boolean ok = crypto.verify(Hexs.decode(kaReq.get("ra")), pileId, Hexs.decode(cloudPublicKey), kaReq.get("t"), kaReq.get("sig"), pileFullPublic);
        if (!ok) {
            System.out.println("[Cloud][Socket] 充电桩签名校验失败，终止协商。");
            send(writer, Map.of("type", "ka_fail"));
            return;
        }
        System.out.println("[Cloud][Socket] 充电桩签名校验通过。");

        // 第四步：Cloud 生成自己的临时 ECDH 密钥对，并返回带签名的响应。
        ClpCrypto.KeyMaterial ephemeral = crypto.generateStaticKey();
        String tb = Instant.now().toString();
        ClpCrypto.Signature sig = crypto.sign(Hexs.decode(ephemeral.publicKeyHex()), cloudId, Hexs.decode(kaReq.get("ra")), tb, cloudFullPrivate);
        Map<String, String> kaResp = new LinkedHashMap<>();
        kaResp.put("type", "ka_response");
        kaResp.put("id", cloudId);
        kaResp.put("publicKey", cloudPublicKey);
        kaResp.put("derivedPublic", cloudDerivedPublic);
        kaResp.put("rb", ephemeral.publicKeyHex());
        kaResp.put("t", tb);
        kaResp.put("sig", sig.toHex());
        System.out.println("[Cloud][Socket] 返回 Cloud 侧签名的 ECDH 响应: rb=" + ephemeral.publicKeyHex());
        send(writer, kaResp);

        String sessionKey = crypto.deriveSessionKey(ephemeral.secretScalar(), Hexs.decode(kaReq.get("ra")),
            Hexs.decode(kaReq.get("ra")), Hexs.decode(ephemeral.publicKeyHex()), pileId, cloudId, kaReq.get("t"), tb);
        System.out.println("[Cloud] 与充电桩 " + pileId + " 协商完成，会话密钥 = " + sessionKey);
    }

    private static void send(BufferedWriter writer, Map<String, String> body) throws Exception {
        System.out.println("[Cloud][Socket] 发送报文: " + body);
        writer.write(SimpleJson.stringify(body));
        writer.write('\n');
        writer.flush();
    }
}