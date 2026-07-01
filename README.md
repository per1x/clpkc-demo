# CL-PKC 三端系统（生产化改造版）

基于无证书公钥密码学（Certificateless PKC）的 KGC / 云平台 / 充电桩三端系统。
本仓库在原始联调 Demo（见 [`legacy-demo/`](legacy-demo/)）基础上做了生产化改造。

## 架构

```
充电桩(C++/OpenSSL) ──TCP 长连接(Socket)──► 云平台(Spring Boot) ──HTTP──► KGC(Spring Boot)
```

- **KGC**：只走 HTTP（TLS 由后续 NGINX 网关统一处理）。主私钥从配置注入。
- **云平台**：Spring Boot 应用，内置 TCP Socket 服务端（对桩，长连接、线程池并发）+ HTTP 客户端（对 KGC）。
- **充电桩**：生产级 C++ 客户端（缓冲 IO、连接/读超时、单行长度上限、nlohmann/json、外置配置、分级日志）。

## 模块

| 目录 | 说明 |
|------|------|
| `clpkc-core/` | 共享密码学库。secp256r1 改用 **BouncyCastle**；CL-PKC 协议原语（H1/H2、点式部分私钥、ECIES、Schnorr、会话密钥、HMAC）。KGC 与云平台共用，保证算法一致。 |
| `kgc-service/` | KGC HTTP 服务（Spring Boot 3 / JDK 17）。 |
| `cloud-service/` | 云平台（Spring Boot 3 / JDK 17）。 |
| `charging-pile/` | 充电桩 C++ 客户端（CMake / OpenSSL）。 |
| `scripts/` | 构建与联调脚本。 |
| `legacy-demo/` | 原始 Demo 存档。 |

## 相对原 Demo 的主要改造

- **曲线实现**：删除手写、非恒定时间的 secp256r1，Java 侧改用 BouncyCastle（P0-2 / P1-8）。
- **KGC 主密钥**：不再每次启动随机生成，改为从配置注入（P0-4）。
- **预共享密钥**：从源码硬编码改为外置配置（全局常量，P0-5）。
- **防重放**：去除时间戳，签名 transcript 与会话密钥改用握手 **nonce** 绑定（P1-6）。
- **并发**：云平台由单线程串行 accept 改为线程池并发（P2-10）。
- **IO 健壮性**：桩端逐字节 read 改为缓冲读 + 超时 + 单行长度上限（P2-11）。
- **日志脱敏**：私钥/会话密钥不落日志，仅输出单向指纹 `SHA256(SK)[0:16]`（P2-12）。
- **JSON/错误处理**：Java 用 Jackson + 参数校验 + 全局异常；C++ 用 nlohmann/json（P2-13）。
- **配置外置**：端口、地址、密钥全部外置到 `application.yml` / `pile.conf`（P2-14）。

> 暂不做：Pile↔Cloud 的 TLS（交给 NGINX）、KGC 调用方鉴权、身份绑定强校验、证书吊销、会话密钥之上的应用数据加密通道。

## 环境要求

- JDK 17+、Maven 3.9+
- CMake ≥ 3.16、C++17 编译器、OpenSSL 开发库

## 构建与运行

```bash
bash ./scripts/build-all.sh   # 构建三端
bash ./scripts/run-demo.sh    # 启动 KGC + 云平台并运行一次充电桩联调
```

联调成功时，云平台与充电桩会打印**相同的会话密钥指纹** `SHA256(SK)[0:16]`，
即证明两套独立实现（Java / C++）派生出同一会话密钥。

## 关键配置

KGC（`kgc-service/src/main/resources/application.yml`）：

| 配置 / 环境变量 | 说明 |
|---|---|
| `clpkc.kgc.master-secret-hex` / `CLPKC_KGC_MASTER_SECRET_HEX` | 主私钥 s（64 hex）。生产必须外置覆盖。 |

云平台（`cloud-service/src/main/resources/application.yml`）：

| 配置 / 环境变量 | 说明 |
|---|---|
| `clpkc.cloud.shared-key-hex` / `CLPKC_CLOUD_SHARED_KEY_HEX` | 与桩的全局预共享密钥。 |
| `clpkc.cloud.static-secret-hex` / `CLPKC_CLOUD_STATIC_SECRET_HEX` | 云平台静态私钥（留空则随机）。 |
| `clpkc.cloud.socket.port` | 对桩 Socket 端口（默认 9000）。 |
| `clpkc.cloud.kgc.base-url` / `CLPKC_KGC_BASE_URL` | KGC 地址。 |

充电桩（`charging-pile/config/pile.conf`，环境变量可覆盖）：
`pile.id` / `cloud.host` / `cloud.port` / `shared.key.hex` / `connect.timeout.ms` / `read.timeout.ms`。

## 协议要点（改造后）

沿用原消息流（`challenge → hmac → auth_ok → partial_key_request → partial_key_response → ka_request → ka_response`），
但 **KA 报文去除 `t` 时间戳字段**，签名 transcript 与会话密钥改绑握手 `nonce`：

- Schnorr transcript = `len‖(ra) ‖ len‖(id) ‖ len‖(wb) ‖ len‖(nonce)`（2 字节大端长度前缀）
- 会话密钥 `SK = SHA256(x(ECDH) ‖ RA ‖ RB ‖ ID_A ‖ ID_B ‖ nonce)`

详见 [`legacy-demo/clpkc-demo/docs/CLPKC_PROTOCOL.md`](legacy-demo/clpkc-demo/docs/CLPKC_PROTOCOL.md)（时间戳相关部分以本节为准）。
