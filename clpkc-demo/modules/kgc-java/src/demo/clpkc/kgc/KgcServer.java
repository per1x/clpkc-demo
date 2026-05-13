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

public final class KgcServer {
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

    private static final class SystemParamsHandler implements HttpHandler {
        private final ClpCrypto crypto;

        private SystemParamsHandler(ClpCrypto crypto) {
            this.crypto = crypto;
        }

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            System.out.println("[KGC] 收到系统参数查询请求: " + exchange.getRequestMethod() + " " + exchange.getRequestURI());
            Map<String, String> body = new LinkedHashMap<>();
            body.put("curve", "secp256r1");
            body.put("masterPublicKey", crypto.getMasterPublicHex());
            writeJson(exchange, 200, body);
        }
    }

    private static final class PartialKeyHandler implements HttpHandler {
        private final ClpCrypto crypto;

        private PartialKeyHandler(ClpCrypto crypto) {
            this.crypto = crypto;
        }

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
            byte[] partialBytes = new Secp256r1().toFixed(crypto.issuePartialPrivate(id, publicKey), 32);
            String encryptedBlob = crypto.eciesEncrypt(partialBytes, publicKey);
            body.put("partialPrivate", encryptedBlob);
            body.put("masterPublicKey", crypto.getMasterPublicHex());
            System.out.println("[KGC] 已生成部分私钥并 ECIES 加密后通过 HTTPS 返回给调用方: id=" + id);
            writeJson(exchange, 200, body);
        }
    }

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
