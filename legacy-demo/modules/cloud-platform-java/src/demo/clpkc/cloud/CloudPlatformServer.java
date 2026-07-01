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

/**
 * Cloud 平台 TCP 服务器。
 *
 * <p>作为 CL-PKC 演示中的 Cloud 端，提供以下功能：
 * <ol>
 *   <li>启动时生成自己的静态密钥对，通过 HTTPS 向 KGC 申请部分私钥，
 *       组合出完整密钥</li>
 *   <li>接受充电桩（Pile）的 TCP 连接，执行四步握手协议：
 *     <ul>
 *       <li><b>第一步</b>：HMAC challenge-response 预共享密钥认证</li>
 *       <li><b>第二步</b>：转发充电桩的部分私钥申请到 KGC，透传结果</li>
 *       <li><b>第三步</b>：接收充电桩带 Schnorr 签名的 ECDH 请求，验签</li>
 *       <li><b>第四步</b>：生成临时 ECDH 密钥对，签名后返回，派生会话密钥</li>
 *     </ul>
 *   </li>
 * </ol>
 *
 * <p>运行参数（通过系统属性配置）：
 * <ul>
 *   <li>{@code cloud.id}：Cloud 身份标识（默认 cloud-001）</li>
 *   <li>{@code kgc.url}：KGC 部分私钥 API 地址</li>
 *   <li>{@code kgc.cert}：KGC TLS 证书 PEM 路径</li>
 *   <li>{@code cloud.port}：TCP 监听端口（默认 9000）</li>
 *   <li>{@code shared.key}：与充电桩的预共享密钥（十六进制）</li>
 * </ul>
 *
 * <p>安全设计要点：</p>
 * <ul>
 *   <li>与 KGC 通信使用 HTTPS + 证书固定</li>
 *   <li>与充电桩通信使用预共享密钥 HMAC 做初始认证</li>
 *   <li>ECDH 请求/响应均附带 Schnorr 签名防止中间人篡改</li>
 *   <li>会话密钥派生绑定了完整的协议 transcript</li>
 * </ul>
 */
public final class CloudPlatformServer {
    /**
     * Cloud 平台服务器入口。
     *
     * <p>启动流程：
     * <ol>
     *   <li>读取系统属性配置（cloud.id、kgc.url、cloud.port、shared.key 等）</li>
     *   <li>生成 Cloud 自己的静态密钥对 (x_cloud, P_cloud)</li>
     *   <li>通过 HTTPS 向 KGC 申请部分私钥，组合出完整密钥 sk_cloud 和 Y_cloud</li>
     *   <li>计算完整公钥 PK_cloud = P_cloud + Y_cloud</li>
     *   <li>启动 TCP ServerSocket，循环接受充电桩连接</li>
     * </ol>
     *
     * @param args 命令行参数（未使用，配置通过系统属性传入）
     * @throws Exception 若任何初始化步骤或网络操作失败
     */
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

    /**
     * 处理单个充电桩连接的完整握手流程。
     *
     * <p>四步握手协议：
     *
     * <h3>第一步：HMAC challenge-response 认证</h3>
     * <ol>
     *   <li>Cloud 生成 16 字节随机 nonce 发送给充电桩</li>
     *   <li>充电桩用预共享密钥对 nonce 做 HMAC-SHA256，返回 mac</li>
     *   <li>Cloud 验算 HMAC，不匹配则发送 auth_fail 并断开</li>
     *   <li>认证通过后，发送 auth_ok 及 Cloud 的公钥/派生公钥</li>
     * </ol>
     *
     * <h3>第二步：转发部分私钥申请</h3>
     * <ol>
     *   <li>充电桩发送其部分私钥申请（id + publicKey）</li>
     *   <li>Cloud 通过 HTTPS 转发给 KGC</li>
     *   <li>将 KGC 返回的加密部分私钥透传给充电桩</li>
     * </ol>
     *
     * <h3>第三步：验证充电桩的签名 ECDH 请求</h3>
     * <ol>
     *   <li>充电桩发送其完整公钥信息和 Schnorr 签名</li>
     *   <li>Cloud 计算充电桩的完整公钥 PK_pile</li>
     *   <li>用 {@link ClpCrypto#verify} 验证签名，失败则终止</li>
     * </ol>
     *
     * <h3>第四步：生成签名 ECDH 响应并派生会话密钥</h3>
     * <ol>
     *   <li>Cloud 生成临时 ECDH 密钥对 (e_cloud, R_cloud)</li>
     *   <li>用 Cloud 完整私钥对 ECDH 响应签名</li>
     *   <li>发送签名后的 ECDH 响应给充电桩</li>
     *   <li>派生会话密钥 sessionKey = H(shared.x || ra || rb || ida || idb || ta || tb)</li>
     * </ol>
     *
     * @param socket             充电桩的 TCP Socket
     * @param crypto             密码学操作模块
     * @param kgcClient          KGC HTTPS 客户端（带证书固定）
     * @param kgcUrl             KGC 部分私钥 API 地址
     * @param sharedKey          与充电桩的预共享密钥（用于 HMAC 初始认证）
     * @param cloudId            Cloud 身份标识
     * @param cloudPublicKey     Cloud 静态公钥 P_cloud（十六进制 SEC1）
     * @param cloudDerivedPublic Cloud 派生公钥 Y_cloud（十六进制 SEC1）
     * @param cloudFullPrivate   Cloud 完整私钥 sk_cloud
     * @param cloudFullPublic    Cloud 完整公钥 PK_cloud（十六进制 SEC1）
     * @throws Exception 若任何 IO 或密码学操作失败
     */
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

    /**
     * 通过 TCP Socket 发送一行 JSON 报文（以换行符分隔）。
     *
     * <p>将 Map 序列化为 JSON 字符串，写入 BufferedWriter，追加换行符并 flush。
     * 日志会输出发送的报文内容。</p>
     *
     * @param writer 输出写入器
     * @param body   待发送的键值对 Map
     * @throws Exception 若写入操作失败
     */
    private static void send(BufferedWriter writer, Map<String, String> body) throws Exception {
        System.out.println("[Cloud][Socket] 发送报文: " + body);
        writer.write(SimpleJson.stringify(body));
        writer.write('\n');
        writer.flush();
    }
}