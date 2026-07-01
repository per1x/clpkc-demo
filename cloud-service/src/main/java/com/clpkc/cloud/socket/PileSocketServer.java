package com.clpkc.cloud.socket;

import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.SmartLifecycle;
import org.springframework.stereotype.Component;

import com.clpkc.cloud.service.CloudIdentity;

/**
 * 对充电桩的 TCP 长连接 Socket 服务端。
 *
 * <p>相对原 Demo 的生产化改造：由单线程串行 accept 改为<b>固定线程池并发</b>处理多桩连接；
 * 随 Spring 生命周期启动/优雅关闭；每连接设读超时与单行长度上限。配置用 {@code @Value} 读取。</p>
 */
@Component
public class PileSocketServer implements SmartLifecycle {

    private static final Logger log = LoggerFactory.getLogger(PileSocketServer.class);

    private final int port;
    private final int backlog;
    private final int readTimeoutMs;
    private final int maxThreads;
    private final CloudIdentity identity;

    private volatile boolean running;
    private ServerSocket serverSocket;
    private ExecutorService acceptExecutor;
    private ThreadPoolExecutor workerPool;

    public PileSocketServer(@Value("${clpkc.cloud.socket.port:9000}") int port,
                            @Value("${clpkc.cloud.socket.backlog:128}") int backlog,
                            @Value("${clpkc.cloud.socket.read-timeout-ms:15000}") int readTimeoutMs,
                            @Value("${clpkc.cloud.socket.max-threads:64}") int maxThreads,
                            CloudIdentity identity) {
        this.port = port;
        this.backlog = backlog;
        this.readTimeoutMs = readTimeoutMs;
        this.maxThreads = maxThreads;
        this.identity = identity;
    }

    @Override
    public void start() {
        try {
            serverSocket = new ServerSocket();
            serverSocket.setReuseAddress(true);
            serverSocket.bind(new InetSocketAddress(port), backlog);
            workerPool = (ThreadPoolExecutor) Executors.newFixedThreadPool(maxThreads,
                namedThreads("pile-worker-"));
            acceptExecutor = Executors.newSingleThreadExecutor(namedThreads("pile-accept-"));
            running = true;
            acceptExecutor.submit(this::acceptLoop);
            log.info("[Cloud] TCP Socket 服务已启动: tcp://0.0.0.0:{}（线程池 {}）", port, maxThreads);
        } catch (Exception e) {
            throw new IllegalStateException("启动 Socket 服务端失败: " + e.getMessage(), e);
        }
    }

    private void acceptLoop() {
        while (running) {
            try {
                Socket socket = serverSocket.accept();
                workerPool.submit(new PileSessionHandler(socket, identity, readTimeoutMs));
            } catch (Exception e) {
                if (running) {
                    log.warn("[Cloud] accept 异常: {}", e.getMessage());
                }
            }
        }
    }

    @Override
    public void stop() {
        running = false;
        closeQuietly();
        shutdown(acceptExecutor);
        shutdown(workerPool);
        log.info("[Cloud] TCP Socket 服务已停止。");
    }

    private void closeQuietly() {
        try {
            if (serverSocket != null) {
                serverSocket.close();
            }
        } catch (Exception ignored) {
            // best-effort
        }
    }

    private void shutdown(ExecutorService pool) {
        if (pool == null) {
            return;
        }
        pool.shutdown();
        try {
            if (!pool.awaitTermination(5, TimeUnit.SECONDS)) {
                pool.shutdownNow();
            }
        } catch (InterruptedException e) {
            pool.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }

    private static java.util.concurrent.ThreadFactory namedThreads(String prefix) {
        java.util.concurrent.atomic.AtomicInteger idx = new java.util.concurrent.atomic.AtomicInteger();
        return r -> {
            Thread t = new Thread(r, prefix + idx.incrementAndGet());
            t.setDaemon(true);
            return t;
        };
    }

    @Override
    public boolean isRunning() {
        return running;
    }
}
