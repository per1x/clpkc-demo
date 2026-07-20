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
| `kgc-service/` | KGC HTTP 服务（Spring Boot 3 / JDK 17，**独立 Maven 工程**）。密码学在自己的 `com.clpkc.kgc.crypto` 包内。 |
| `cloud-service/` | 云平台（Spring Boot 3 / JDK 17，**独立 Maven 工程**）。密码学在自己的 `com.clpkc.cloud.crypto` 包内（与 KGC 各一份）。 |
| `charging-pile/` | 充电桩 C++ 客户端（CMake / OpenSSL）。 |
| `scripts/` | 构建与联调脚本。 |
| `legacy-demo/` | 原始 Demo 存档。 |

> 密码学库（`Hex`/`EcCurve`/`ClpkcCrypto`）**不做共享模块，各服务各自持有一份**；每个服务是独立工程，可单独 `mvn -f <service>/pom.xml package`。国密 SM2+SM3（BouncyCastle），隐式证书方案（`WA`/`λ`/`tA`、`dA=tA+ua`、`PA=WA+λ·Ppub`）。

## 相对原 Demo 的主要改造

- **国密算法 + 隐式证书方案**：切换到 **SM2 + SM3 + HMAC-SM3**，无证书部分采用**隐式证书（ECQV/SM2 风格）**——与现网 KGC 对齐：KGC 出 `WA=wG+UA`、`tA=(w+λ·ms) mod n`，设备合成 `dA=tA+ua`，验证方用 `PA=WA+λ·Ppub` **重构公钥、无需预存**。Java 用 BouncyCastle、C++ 用 OpenSSL；SM2 密文 = C1C3C2 原始拼接（桩端手动解密），SM2 签名线上格式 = 裸 `r‖s`（64 字节），均已跨实现互通验证（P0-2 / P1-8）。
- **KGC 主密钥**：不再每次启动随机生成，改为从配置注入（P0-4）。
- **预共享密钥**：从源码硬编码改为外置配置（全局常量，P0-5）。
- **防重放**：去除时间戳，签名 transcript 与会话密钥改用握手 **nonce** 绑定（P1-6）。
- **并发**：云平台由单线程串行 accept 改为线程池并发（P2-10）。
- **IO 健壮性**：桩端逐字节 read 改为缓冲读 + 超时 + 单行长度上限（P2-11）。
- **日志脱敏**：私钥/会话密钥不落日志，仅输出单向指纹 `SM3(SK)[0:16]`（P2-12）。
- **JSON/错误处理**：Java 用 Jackson + 参数校验 + 全局异常；C++ 用 nlohmann/json（P2-13）。
- **配置外置**：端口、地址、密钥全部外置到 `application.properties` / `pile.conf`（P2-14）。

> 暂不做：Pile↔Cloud 的 TLS（交给 NGINX）、KGC 调用方鉴权、身份绑定强校验、证书吊销、会话密钥之上的应用数据加密通道。

## 环境要求

- JDK 17+、Maven 3.9+
- CMake ≥ 3.16、C++17 编译器、OpenSSL 开发库

## 构建与运行

```bash
bash ./scripts/build-all.sh   # 构建三端
bash ./scripts/run-demo.sh    # 启动 KGC + 云平台并运行一次充电桩联调
```

联调成功时，云平台与充电桩会打印**相同的会话密钥指纹** `SM3(SK)[0:16]`，
即证明两套独立实现（Java / C++）派生出同一会话密钥。

## 关键配置

KGC（`kgc-service/src/main/resources/application.properties`）：

| 配置 / 环境变量 | 说明 |
|---|---|
| `clpkc.kgc.master-secret-hex` / `CLPKC_KGC_MASTER_SECRET_HEX` | 主私钥 s（64 hex）。生产必须外置覆盖。 |

云平台（`cloud-service/src/main/resources/application.properties`）：

| 配置 / 环境变量 | 说明 |
|---|---|
| `clpkc.cloud.shared-key-hex` / `CLPKC_CLOUD_SHARED_KEY_HEX` | 与桩的全局预共享密钥（16 字节 SM4 密钥，32 hex）。 |
| `clpkc.cloud.static-secret-hex` / `CLPKC_CLOUD_STATIC_SECRET_HEX` | 云平台静态私钥（留空则随机）。 |
| `clpkc.cloud.socket.port` | 对桩 Socket 端口（默认 9000）。 |
| `clpkc.cloud.kgc.base-url` / `CLPKC_KGC_BASE_URL` | KGC 地址。 |

充电桩（`charging-pile/config/pile.conf`，环境变量可覆盖）：
`pile.id` / `cloud.host` / `cloud.port` / `shared.key.hex` / `connect.timeout.ms` / `read.timeout.ms`。

## 协议要点（改造后）

**两阶段拆分**：桩（主机）发起，云平台**不再下发 challenge**——桩自生成本次会话的新鲜 `nonce`（16 字节，绑定签名防重放）并随首报文发给云，云只复用不重新生成；云按桩发来的报文类型分流：

- **第一阶段（仅首次，provision）**：**双向 HMAC-SM3 挑战应答**（4 条报文）——桩发 `hmac(id, publicKey, randomB)` → 云回 `hmac_challenge(mac=HMAC(PSK,randomB), randomA)` 自证身份并反向挑战 → 桩**验证云的 MAC**（不过即中止）后回 `hmac_response(mac=HMAC(PSK,randomA))` → 云验证通过回 `auth_ok`。随后 `partial_key_request` → 云平台转发 KGC → `partial_key_response(claimedPublic WA, partialPrivate, masterPublicKey)`。桩组合 `dA` 后**本地持久化**（`pile-keystore.json`）。`random_A`/`random_B` 各 16 字节、每次连接新鲜生成。
- **第二阶段（每次会话，session）**：桩加载本地密钥，直接发 `ka_request(id, claimedPublic, rB, nonce, sig)`（msg1）→ 云平台核对桩编号(见 `PileDirectory`)、重构 `PA` 验发起方签名 → 回 `ka_response`（msg2，含云临时公钥 `rA` 与响应方签名）→ 双方派生会话密钥。**不再走 HMAC、不再申请 KGC。**

密码学细节：

- 身份摘要 `HA = SM3(len2B(id) ‖ id ‖ a ‖ b ‖ Gx ‖ Gy ‖ Ppub.x ‖ Ppub.y)`；`λ = SM3(WA.x ‖ WA.y ‖ HA)`
- 完整密钥 `dA = (tA + ua) mod n`，`PA = WA + λ·Ppub`（验证方重构，无需预存公钥）
- SM2 签名 transcript（**全定长字段直拼、无长度前缀**）：发起方（桩）签 `R_B ‖ ID_B ‖ W_B ‖ nonce`，响应方（云）签 `R_A ‖ R_B ‖ ID_A ‖ W_A ‖ nonce`；ID 定长 32 字节右侧 0x00 补齐；签名线上格式为裸 `r‖s`（64 字节）
- 会话密钥 `SK = SM3(x(ECDH) ‖ RA ‖ RB ‖ ID_A ‖ ID_B ‖ nonce)`
- 点线上编码 `x(32)‖y(32)`（128 hex，无 04 前缀）；配置文件为 `.properties` 格式

详见 [`legacy-demo/clpkc-demo/docs/CLPKC_PROTOCOL.md`](legacy-demo/clpkc-demo/docs/CLPKC_PROTOCOL.md)（时间戳相关部分以本节为准）。
