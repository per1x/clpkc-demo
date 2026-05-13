package demo.clpkc.cloud;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Map;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

public final class HttpsJsonClient {
    private final HttpClient client;

    public HttpsJsonClient(Path certPem) throws Exception {
        // Cloud 只信任 KGC 的自签名证书，避免被本地其他 HTTPS 服务冒充。
        this.client = HttpClient.newBuilder().sslContext(buildSslContext(certPem)).build();
    }

    public Map<String, String> post(String url, Map<String, String> body) throws IOException, InterruptedException {
        String requestJson = SimpleJson.stringify(body);
        System.out.println("[Cloud][HTTPS] 发送 HTTPS POST 请求到 KGC: " + url);
        System.out.println("[Cloud][HTTPS] 请求体: " + requestJson);
        HttpRequest request = HttpRequest.newBuilder(URI.create(url))
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(requestJson, StandardCharsets.UTF_8))
            .build();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        System.out.println("[Cloud][HTTPS] 收到 KGC 响应: 状态码=" + response.statusCode() + ", 响应体=" + response.body());
        return SimpleJson.parse(response.body());
    }

    private SSLContext buildSslContext(Path certPem) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Certificate cert;
        try (var in = Files.newInputStream(certPem)) {
            cert = cf.generateCertificate(in);
        }
        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        trustStore.load(null, null);
        trustStore.setCertificateEntry("kgc", cert);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);
        SSLContext ssl = SSLContext.getInstance("TLS");
        ssl.init(null, tmf.getTrustManagers(), null);
        return ssl;
    }
}
