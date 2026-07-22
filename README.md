# CL-PKC 三端系统

基于无证书公钥密码学（Certificateless PKC）的 KGC / 云平台 / 充电桩三端系统，
采用国密 SM2/SM3/HMAC-SM3 与隐式证书（ECQV/SM2 风格）方案。

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
| `pile-sdk/` | 桩端（主机端）密码学 SDK（C++17 / OpenSSL），含 KAT 测试向量。**充电桩的密码学实现唯一来源**。 |
| `docs/` | 对外文档：[`SPEC_FEEDBACK.md`](docs/SPEC_FEEDBACK.md) 为技术联络单附录 A.3 的修订建议清单。 |
| `legacy-demo/` | 早期联调 Demo 存档，不参与构建。 |

> 密码学库（`Hex`/`EcCurve`/`ClpkcCrypto`）**不做共享模块，各服务各自持有一份**；每个服务是独立工程，可单独 `mvn -f <service>/pom.xml package`。国密 SM2+SM3（BouncyCastle），隐式证书方案（`WA`/`λ`/`tA`、`dA=tA+ua`、`PA=WA+λ·Ppub`）。

## 实现要点

- **国密算法 + 隐式证书方案**：**SM2 + SM3 + HMAC-SM3**，无证书部分采用**隐式证书（ECQV/SM2 风格）**——与现网 KGC 对齐：KGC 出 `WA=wG+UA`、`tA=(w+λ·ms) mod n`，设备合成 `dA=tA+ua`，验证方用 `PA=WA+λ·Ppub` **重构公钥、无需预存**。Java 用 BouncyCastle、C++ 用 OpenSSL；SM2 密文 = C1C3C2 原始拼接（桩端手动解密），SM2 签名线上格式 = 裸 `r‖s`（64 字节），两套实现跨语言互通（见 [`pile-sdk/kat.md`](pile-sdk/kat.md)）。
- **KGC 主密钥**：从配置注入，进程重启不变。
- **预共享密钥**：外置配置（桩与云共享的全局常量）。
- **防重放**：签名 transcript 与会话密钥均绑定握手 **nonce**（不使用时间戳）。
- **并发**：云平台 TCP Socket 服务端用线程池并发处理桩连接。
- **IO 健壮性**：桩端缓冲读 + 连接/读超时 + 单行长度上限。
- **日志脱敏**：私钥/会话密钥不落日志，仅输出单向指纹 `SM3(SK)[0:16]`。
- **JSON/错误处理**：Java 用 Jackson + 参数校验 + 全局异常；C++ 用 nlohmann/json。
- **配置外置**：端口、地址、密钥全部在 `application.properties` / `pile.conf` 中配置。

> 范围外（当前不实现）：Pile↔Cloud 的 TLS（交给 NGINX）、KGC 调用方鉴权、身份绑定强校验、证书吊销、会话密钥之上的应用数据加密通道。

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
`pile.host_no`(主机编号，≤14 位十进制) / `cloud.host` / `cloud.port` / `shared.key.hex` / `connect.timeout.ms` / `read.timeout.ms`。

## 协议要点

**两阶段拆分**：桩（主机）发起，云平台不下发 challenge——桩自生成本次会话的新鲜 `nonce`（16 字节，绑定签名防重放）并随首报文发给云，云复用该 nonce；云按桩发来的报文类型分流：

- **第一阶段（仅首次，provision）**：**双向 HMAC-SM3 挑战应答**（4 条报文）——桩发 `hmac(id, publicKey, randomB)` → 云回 `hmac_challenge(mac=HMAC(PSK,randomB), randomA)` 自证身份并反向挑战 → 桩**验证云的 MAC**（不过即中止）后回 `hmac_response(mac=HMAC(PSK,randomA))` → 云验证通过回 `auth_ok`。随后 `partial_key_request` → 云平台转发 KGC → `partial_key_response(claimedPublic WA, partialPrivate, masterPublicKey)`。桩组合 `dA` 后**本地持久化**（`pile-keystore.json`）。`random_A`/`random_B` 各 16 字节、每次连接新鲜生成。
- **第二阶段（每次会话，session）**：桩加载本地密钥，直接发 `ka_request(id, claimedPublic, rB, nonce, sig)`（msg1）→ 云平台核对桩编号(见 `PileDirectory`)、重构 `PA` 验发起方签名 → 回 `ka_response`（msg2，含云临时公钥 `rA` 与响应方签名）→ 双方派生会话密钥。本阶段不涉及 HMAC 认证与 KGC 申请。

密码学细节：

- **编码总则：所有进哈希/签名的字段一律使用「解码后的原始字节」，绝不使用 hex 文本**（hex 只是配置与接口的传参形式）。
  各字段进哈希时的字节数：曲线点 64、ID 32、nonce 16、`Sx` 32、签名 `r‖s` 各 32。
- **ID 统一 32 字节**：transcript、会话密钥 KDF、身份摘要 HA(算 λ)、SM2 签名 ZA **四处一致**，ENTL 恒为 `0x0100`(=256bit)。
  线上报文与 KGC HTTP 接口的 `id` 字段一律传 **64 字符 hex**（32 字节 ID 的十六进制），收到后解码成 32 字节直接进密码学层。
  - **桩 ID_B** = 7 字节 BCD 主机编号 ‖ 25 字节 `0x00`。主机编号为 ≤14 位十进制数字串，
    **不足 14 位左侧补 `'0'`**（保持数值不变，如 `1` → `00000000000001`）。配置 `pile.host_no` / `CLPKC_PILE_HOST_NO`。
  - **云 ID_A** = 域名 ASCII 字节 ‖ `0x00` 补齐到 32 字节。配置 `clpkc.cloud.id`（如 `cloud.example.com`）。
  - 字节级示例：
    ```
    ID_B: 00 00 00 00 00 00 01 | 00 × 25                  (主机编号 00000000000001)
    ID_A: 63 6c 6f 75 64 2e 65 78 61 6d 70 6c 65 2e 63 6f 6d | 00 × 15   ("cloud.example.com")
    ```
  - ID 超 32 字节 / 主机编号超 14 位或含非十进制字符 → **直接报错**（不截断）。
- 身份摘要 `HA = SM3(0x0100 ‖ ID32 ‖ a ‖ b ‖ Gx ‖ Gy ‖ Ppub.x ‖ Ppub.y)`；`λ = SM3(WA.x ‖ WA.y ‖ HA)`
- 完整密钥 `dA = (tA + ua) mod n`，`PA = WA + λ·Ppub`（验证方重构，无需预存公钥）
- SM2 签名 transcript（**全定长字段直拼、无长度前缀**）：发起方（桩）签 `R_B ‖ ID_B ‖ W_B ‖ nonce`，响应方（云）签 `R_A ‖ R_B ‖ ID_A ‖ W_A ‖ nonce`；ID 为上述 32 字节形态；签名线上格式为裸 `r‖s`（64 字节）
- 会话密钥 `SK = SM3(Sx ‖ R_A ‖ R_B ‖ ID_A ‖ ID_B ‖ nonce)`，单次 SM3，输出 32 字节。
  `Sx` 为本方临时私钥 × 对端临时公钥所得点的 X 坐标（32 字节定长）。
- **SM4 密钥**取会话密钥 `SK` 的**前 16 字节**。
- 点线上编码 `x(32)‖y(32)`（128 hex，无 04 前缀）；配置文件为 `.properties` 格式

### 字段长度表

| 字段 | 长度 | 说明 |
|---|---|---|
| 曲线点 `UA`/`WA`/`R_A`/`R_B`/`Ppub`/`PA` | **64 字节** | 裸 `X‖Y`，128 hex，不含 `04` 前缀 |
| 标量 `ua`/`tA`/`dA`/临时私钥 | **32 字节** | 大端定长，左侧补 0，64 hex |
| `ID_A` / `ID_B` | **32 字节** | 见上；线上传 64 hex |
| `nonce` | **16 字节** | 进 transcript/KDF 用原始字节 |
| `random_A` / `random_B` | **16 字节** | 第一阶段挑战值，进 HMAC 用原始字节 |
| SM2 签名 | **64 字节** | 裸 `r‖s`，各 32 字节定长，128 hex |
| HMAC-SM3 输出 | **32 字节** | 64 hex |
| SM2 密文（部分私钥） | **129 字节** | C1C3C2：C1(65，含 `04`) ‖ C3(32) ‖ C2(32)，258 hex |
| 会话密钥 `SK` | **32 字节** | SM4 密钥取其前 16 字节 |
| `HA` / `λ` | **32 字节** | SM3 输出；`λ` 按大端无符号整数取用 |

算法与测试向量的完整说明见 [`pile-sdk/README.md`](pile-sdk/README.md) 与 [`pile-sdk/kat.md`](pile-sdk/kat.md)。
