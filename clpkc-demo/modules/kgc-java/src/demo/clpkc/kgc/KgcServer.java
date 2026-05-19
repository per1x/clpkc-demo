package demo.clpkc.kgc;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.util.LinkedHashMap;
import java.util.Map;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

/**
 * CL-PKC 密钥生成中心（KGC）的 HTTPS 服务器。
 *
 * <p>KGC 是 CL-PKC（无证书公钥密码学）体系中的可信第三方，
 * 负责生成系统参数并安全地为客户端颁发部分私钥。</p>
 *
 * <p>提供以下 HTTPS API 端点：</p>
 * <ul>
 *   <li>{@code GET /api/system-params} — 获取系统参数（曲线名称、主公钥）。</li>
 *   <li>{@code POST /api/partial-key} — 提交客户端身份和公钥，获取加密的部分私钥。</li>
 * </ul>
 *
 * <h3>配置项（通过 Java 系统属性指定）</h3>
 * <ul>
 *   <li>{@code kgc.port} — HTTPS 监听端口，默认 8443。</li>
 *   <li>{@code kgc.keystore} — PKCS12 密钥库文件路径，默认 {@code certs/kgc-keystore.p12}。</li>
 *   <li>{@code kgc.storepass} — 密钥库密码，默认 {@code changeit}。</li>
 * </ul>
 *
 * <h3>安全注意事项</h3>
 * <ul>
 *   <li>所有通信必须通过 HTTPS/TLS 加密，防止中间人攻击窃取部分私钥。</li>
 *   <li>部分私钥在响应中使用 ECIES 加密，即使 TLS 层被攻破也不会泄露明文。</li>
 *   <li>密钥库文件（.p12）必须妥善保管，设置强密码。</li>
 *   <li>生产环境必须使用由受信任 CA 签发的证书，而非自签名证书。</li>
 * </ul>
 *
 * @see ClpCrypto
 * @see Secp256r1
 */
public final class KgcServer {

    /**
     * KGC 服务器入口点。
     *
     * <p>启动流程：
     * <ol>
     *   <li>从系统属性读取端口、密钥库路径和密码。</li>
     *   <li>创建 TLS/SSL 上下文（加载 PKCS12 密钥库）。</li>
     *   <li>初始化 CL-PKC 密码学模块（生成主密钥对）。</li>
     *   <li>创建并配置 HTTPS 服务器。</li>
     *   <li>注册两个 API 端点：系统参数查询和部分私钥颁发。</li>
     *   <li>启动服务器并打印主公钥信息。</li>
     * </ol></p>
     *
     * <p>安全说明：启动后控制台输出的主公钥信息不包含敏感的主私钥，
     * 仅主公钥可安全公开。</p>
     *
     * @param args 命令行参数（未使用，配置通过系统属性指定）
     * @throws Exception 如果密钥库加载失败或服务器启动失败
     */
    public static void main(String[] args) throws Exception {
        int port = Integer.parseInt(System.getProperty("kgc.port", "8443"));
        Path keystore = Path.of(System.getProperty("kgc.keystore", "certs/kgc-keystore.p12"));
        char[] password = System.getProperty("kgc.storepass", "changeit").toCharArray();
        SSLContext sslContext = createSslContext(keystore, password);
        ClpCrypto crypto = new ClpCrypto();

        HttpsServer server = HttpsServer.create(new InetSocketAddress(port), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(sslContext) {
            @Override
            public void configure(HttpsParameters params) {
                params.setSSLParameters(getSSLContext().getDefaultSSLParameters());
            }
        });
        server.createContext("/api/system-params", new SystemParamsHandler(crypto));
        server.createContext("/api/partial-key", new PartialKeyHandler(crypto));
        server.start();
        System.out.println("[KGC] HTTPS 服务已启动: https://0.0.0.0:" + port);
        System.out.println("[KGC] 当前系统主公钥 = " + crypto.getMasterPublicHex());
    }

    /**
     * 创建 TLS/SSL 上下文：加载 PKCS12 密钥库并初始化 TLS。
     *
     * <p>该方法的处理流程：
     * <ol>
     *   <li>从文件系统加载 PKCS12 格式的密钥库。</li>
     *   <li>使用密钥库初始化密钥管理器（KeyManager），用于 TLS 握手时
     *       向客户端出示服务器证书。</li>
     *   <li>使用密钥库初始化信任管理器（TrustManager），用于验证客户端证书
     *       （如果启用了双向 TLS）。</li>
     *   <li>创建 TLS 协议的 SSLContext 实例。</li>
     * </ol></p>
     *
     * <p>安全说明：
     * <ul>
     *   <li>密钥库密码以 char[] 形式传递（而非 String），减少在内存中
     *       以不可变字符串形式存在的时间。</li>
     *   <li>生产环境中建议仅使用 TLS 1.2+，禁用不安全的旧协议版本。</li>
     * </ul></p>
     *
     * @param keystoreFile PKCS12 密钥库文件路径
     * @param password     密钥库密码（字符数组，使用后可清零）
     * @return 配置好的 SSLContext 实例
     * @throws Exception 如果密钥库文件不存在、密码错误或 TLS 初始化失败
     */
    private static SSLContext createSslContext(Path keystoreFile, char[] password) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(keystoreFile)) {
            keyStore.load(in, password);
        }
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, password);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(keyStore);
        SSLContext ssl = SSLContext.getInstance("TLS");
        ssl.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        return ssl;
    }

    /**
     * 系统参数查询处理器。
     *
     * <p>处理 {@code GET /api/system-params} 请求，返回 CL-PKC 系统参数：
     * <ul>
     *   <li>{@code curve}：椭圆曲线名称（固定为 {@code "secp256r1"}）。</li>
     *   <li>{@code masterPublicKey}：KGC 主公钥的十六进制字符串。</li>
     * </ul>
     * </p>
     *
     * <p>安全说明：这些参数可以公开分发，不包含任何密钥材料。
     * 客户端使用主公钥验证部分私钥的正确性（通过检查 ê(D_i, Q_i) = ê(Ppub, Q_i)）。</p>
     */
    private static final class SystemParamsHandler implements HttpHandler {

        /** CL-PKC 密码学实例引用。 */
        private final ClpCrypto crypto;

        /**
         * 构造系统参数处理器。
         *
         * @param crypto CL-PKC 密码学实例（用于获取主公钥）
         */
        private SystemParamsHandler(ClpCrypto crypto) {
            this.crypto = crypto;
        }

        /**
         * 处理 HTTP 请求：返回系统参数（曲线名称和主公钥）的 JSON 响应。
         *
         * <p>该方法对所有 HTTP 方法均返回相同内容。
         * 响应状态码固定为 200 OK。</p>
         *
         * @param exchange HTTP 交换对象，包含请求和响应信息
         * @throws IOException 如果写入响应体失败
         */
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            System.out.println("[KGC] 收到系统参数查询请求: " + exchange.getRequestMethod() + " " + exchange.getRequestURI());
            Map<String, String> body = new LinkedHashMap<>();
            body.put("curve", "secp256r1");
            body.put("masterPublicKey", crypto.getMasterPublicHex());
            writeJson(exchange, 200, body);
        }
    }

    /**
     * 部分私钥颁发处理器。
     *
     * <p>处理 {@code POST /api/partial-key} 请求。客户端提交身份标识 ID
     * 和静态公钥 P_i，KGC 计算部分私钥 D_i = s · H1(ID || P_i)，
     * 并使用 ECIES 加密后返回。</p>
     *
     * <h3>请求格式（JSON）</h3>
     * <pre>{@code
     * {
     *   "id": "alice@example.com",
     *   "publicKey": "04<64 hex x><64 hex y>"
     * }
     * }</pre>
     *
     * <h3>响应格式（JSON）</h3>
     * <pre>{@code
     * {
     *   "curve": "secp256r1",
     *   "partialPrivate": "<ECIES 加密后的部分私钥 HEX>",
     *   "masterPublicKey": "<主公钥 HEX>"
     * }
     * }</pre>
     *
     * <p>安全说明：
     * <ul>
     *   <li>部分私钥使用 ECIES 加密，密钥派生自接收方的静态公钥。</li>
     *   <li>只有持有对应静态私钥的客户端才能解密部分私钥。</li>
     *   <li>即使攻击者截获加密的部分私钥，没有客户端私钥也无法解密。</li>
     * </ul></p>
     */
    private static final class PartialKeyHandler implements HttpHandler {

        /** CL-PKC 密码学实例引用。 */
        private final ClpCrypto crypto;

        /**
         * 构造部分私钥处理器。
         *
         * @param crypto CL-PKC 密码学实例（用于生成和加密部分私钥）
         */
        private PartialKeyHandler(ClpCrypto crypto) {
            this.crypto = crypto;
        }

        /**
         * 处理 HTTP 请求：接收客户端身份和公钥，颁发加密的部分私钥。
         *
         * <p>处理流程：
         * <ol>
         *   <li>解析请求体中的 JSON，提取 {@code id} 和 {@code publicKey}。</li>
         *   <li>调用 {@link ClpCrypto#issuePartialPrivate} 生成部分私钥 D_i。</li>
         *   <li>将 D_i 编码为 SEC1 非压缩格式的字节数组。</li>
         *   <li>使用 {@link ClpCrypto#eciesEncrypt} 加密编码后的部分私钥。</li>
         *   <li>返回包含加密部分私钥和主公钥的 JSON 响应。</li>
         * </ol></p>
         *
         * @param exchange HTTP 交换对象，包含请求和响应信息
         * @throws IOException 如果读取请求体或写入响应体失败
         */
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String request = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            Map<String, String> req = SimpleJson.parse(request);
            String id = req.get("id");
            String publicKey = req.get("publicKey");
            System.out.println("[KGC] 收到部分私钥申请: id=" + id);
            System.out.println("[KGC] 申请方静态公钥 P_i = " + publicKey);
            Map<String, String> body = new LinkedHashMap<>();
            body.put("curve", "secp256r1");
            Secp256r1.Point D_i = crypto.issuePartialPrivate(id, publicKey);
            byte[] partialBytes = crypto.curve().encode(D_i);
            String encryptedBlob = crypto.eciesEncrypt(partialBytes, publicKey);
            body.put("partialPrivate", encryptedBlob);
            body.put("masterPublicKey", crypto.getMasterPublicHex());
            System.out.println("[KGC] 已生成部分私钥并 ECIES 加密后通过 HTTPS 返回给调用方: id=" + id);
            writeJson(exchange, 200, body);
        }
    }

    /**
     * 将 Map 序列化为 JSON 字符串并通过 HTTP 响应发送。
     *
     * <p>设置响应头为 {@code Content-Type: application/json; charset=utf-8}，
     * 确保客户端正确解析 UTF-8 编码的中文字符。</p>
     *
     * <p>安全说明：响应体内容会被记录到控制台日志中。
     * 生产环境应关闭详细日志或脱敏处理，避免泄露加密的部分私钥。</p>
     *
     * @param exchange HTTP 交换对象
     * @param status   HTTP 状态码（如 200、400 等）
     * @param body     要序列化为 JSON 的键值对
     * @throws IOException 如果写入响应体失败
     */
    private static void writeJson(HttpExchange exchange, int status, Map<String, String> body) throws IOException {
        byte[] payload = SimpleJson.stringify(body).getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        exchange.sendResponseHeaders(status, payload.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(payload);
        }
        System.out.println("[KGC] 响应完成: status=" + status + ", body=" + SimpleJson.stringify(body));
    }
}
