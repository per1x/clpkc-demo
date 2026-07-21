# CL-PKC 桩端(主机端) 密码学 SDK

国密 **SM2 / SM3 / HMAC-SM3** + 隐式证书（ECQV/SM2 风格）的无证书公钥密码学算法库，
供充电桩（主机端）集成。C++17 + OpenSSL 3.x，单静态库，无第三方依赖。

## ⚠️ 范围界定：本 SDK 只提供密码学算法

**包含**：密钥生成、随机数、HMAC-SM3、SM2 解密/签名/验签、隐式证书公私钥合成与重建、
会话密钥派生、编码辅助。全部为**纯函数、无状态、线程安全**。

**不包含（由集成方自行实现）**：

| 不做 | 说明 |
|---|---|
| 存储 / keystore | 私钥、`W`、`Ppub` 如何持久化由主机端决定 |
| 网络通信 | 不含 socket、连接、超时、重连 |
| 报文封装 / 解析 | 不含帧头、长度、校验、序列号、报文类型 |
| 流程编排 | 不含"先开通再协商"的状态机、重试、失败回退 |
| 时间戳 / 会话管理 | 不含 CP56Time2a、UUID、会话生命周期 |

SDK 只回答"这段字节的密码学结果是什么"，不回答"什么时候发给谁"。

---

## 构建

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
cd build && make test        # 跑 KAT 自检（等价 ctest）
```

产物：`libclpkc_sdk.a` + `clpkc_sdk.h`。集成时链接 `OpenSSL::Crypto` 即可。

要求：**OpenSSL 3.0+**（需含 SM2/SM3 算法）、C++17。

---

## 通用约定（**接入前必读**）

| 项 | 约定 |
|---|---|
| **数据形式** | 所有入参/返回值都是 **hex 字符串**。输入大小写不敏感，输出**一律小写**。 |
| **字节序** | 多字节整数/标量一律**大端**。 |
| **曲线点** | **64 字节裸 `X‖Y`（128 hex，不含 `04` 前缀）**。需要 SEC1 时用 `point_from_wire`。 |
| **标量 / 私钥** | 32 字节（64 hex），左侧补 0 至定长。 |
| **签名** | **64 字节裸 `r‖s`（128 hex），非 DER。** |
| **ID** | **32 字节（64 hex）**，不足右侧补 `0x00`。用 `make_id_from_ascii` / `make_id_from_bcd` 构造。 |
| **ENTL** | 因 ID 定长 32 字节，SM2 的 ENTL **恒为 `0x0100`**（256 bit）。 |
| **SM2 密文** | C1C3C2 原始拼接，**C1 含 `04`**，共 **129 字节（258 hex）**。 |

### 核心规则与一个易踩的坑

1. **规则：所有进哈希/签名的字段一律使用「解码后的原始字节」，绝不使用 hex 文本。**
   hex 字符串只是 API 的传参形式，进 SM3/HMAC/签名前一律先解码。
   nonce 也不例外：传入 32 字符 hex，内部一律解码为 **16 原始字节**，
   在 transcript / KDF / HMAC **三处完全一致**（长度不符直接报错）。

2. **ID 必须是 32 字节 hex，不是 ASCII 串**。先调 `make_id_from_ascii("pile-001")` 得到
   64 hex，再传给其它函数。ID 是唯一"以标识符自身字节参与"的字段（ASCII 零补齐到 32 字节），
   这与"原始字节"规则一致——它本来就不是 hex 编码的值。

---

## 接口一览

### 1. 密钥与随机数

```cpp
KeyPair generate_keypair();                 // {secret_hex:64, public_hex:128}
std::string random_bytes_hex(int n_bytes);  // 返回 2*n_bytes hex
```
`generate_keypair` 同时用于长期密钥 `(d_B, U_B)` 与临时密钥 `(b, R_B)`。

### 2. HMAC-SM3（第一阶段挑战应答）

```cpp
std::string hmac_sm3_hex(key_hex, data_hex);                 // → 32 字节(64 hex)
bool hmac_sm3_verify(key_hex, data_hex, expected_mac_hex);   // 常量时间比较
```
`key_hex` / `data_hex` **均先 hex 解码**再计算。校验对端 MAC **必须**用
`hmac_sm3_verify`（常量时间，防时序侧信道），不要自己用 `==` 比字符串。

### 3. 隐式证书

```cpp
std::string sm2_decrypt(d_hex, cipher_hex);                       // → t_hex
std::string compose_full_private(d_hex, t_hex);                   // SK=(d+t) mod n
std::string reconstruct_full_public(id_hex, w_hex, ppub_hex);     // PK=W+λ·Ppub
bool verify_keypair_consistency(sk_hex, w_hex, ppub_hex, id_hex); // SK·G == PK ?
```
- `sm2_decrypt` 单独暴露，便于开通失败时定位是"解密错"还是"合成错"。
- 计算式：
  - `HA = SM3(0x0100 ‖ ID32 ‖ a ‖ b ‖ Gx ‖ Gy ‖ Ppub.x ‖ Ppub.y)`
  - `λ  = SM3(W.x ‖ W.y ‖ HA)`（按大端无符号整数取用）
  - `PK = W + λ·Ppub`
- **开通落地后建议调一次 `verify_keypair_consistency`**，确认密钥对自洽再持久化。

### 4. 签名 / 验签

```cpp
std::string sign_initiator(rB_hex, idB_hex, wB_hex, nonce_hex, sk_hex);
bool verify_responder(rA_hex, rB_hex, idA_hex, wA_hex, nonce_hex, sig_raw_hex, pk_hex);
bool verify_initiator(rB_hex, idB_hex, wB_hex, nonce_hex, sig_raw_hex, pk_hex);  // 附加，自检用
```
transcript（**全定长字段直拼、无长度前缀**）：
- 发起方（主机）：`R_B ‖ ID_B ‖ W_B ‖ nonce_ascii`
- 响应方（云）：`R_A ‖ R_B ‖ ID_A ‖ W_A ‖ nonce_ascii`

ZA 用户标识使用 **32 字节 ID**（ENTL=0x0100）。
> SM2 签名含随机 k，**同样输入每次签出的值不同，属正常**；验签结果才是判定依据。

### 5. 会话密钥

```cpp
std::string derive_session_key(eph_secret_hex, peer_point_hex,
                               rA_hex, rB_hex, idA_hex, idB_hex, nonce_hex);
std::string session_key_to_sm4(sk32_hex);   // 取前 16 字节
```
`SK = SM3(Sx ‖ R_A ‖ R_B ‖ ID_A ‖ ID_B ‖ nonce_ascii)`，**单次 SM3**，输出 32 字节。
`Sx` = 本方临时私钥 × 对端临时公钥 得到点的 X 坐标。
主机端调用时：`eph_secret = b`（自己的临时私钥），`peer_point = R_A`（云的临时公钥）。

> `session_key_to_sm4` 取**前 16 字节**。此取用规则原规范未定义，为本 SDK 的约定，**待双方确认**。

### 6. 编码辅助

```cpp
std::string make_id_from_ascii(ascii);      // "pile-001" → 32B hex
std::string make_id_from_bcd(bcd_hex);      // 7 字节 BCD → 32B hex（前 7 字节）
std::string point_to_wire(point_hex);       // 65B SEC1 或 64B 裸点 → 64B 裸点
std::string point_from_wire(wire_hex);      // 64B 裸点 → 65B SEC1(04‖X‖Y)
std::string sm3_hex(data_hex);              // → 32B hex
```
> `make_id_from_ascii` 与 `make_id_from_bcd` **二选一**，取决于现网主机编号的实际形态，
> **待与对方确认后选用**。两者都提供，切换只需改构造 ID 这一行。

---

## 错误处理

| 情况 | 行为 |
|---|---|
| 入参格式非法（hex 非法、长度不符、点不在曲线上）、内部运算失败 | 抛 **`clpkc::Error`**（派生自 `std::runtime_error`） |
| `verify_responder` / `verify_initiator` / `verify_keypair_consistency` / `hmac_sm3_verify` | **不抛异常**，一律返回 `bool`；签名不匹配**和**入参非法都返回 `false` |

集成建议：对所有非 `verify_*` 调用包 `try/catch(const clpkc::Error&)`，把 `what()` 记进日志。
长度不符会**立即报错而非静默截断/补齐**，以避免跨端悄悄算出不同结果。

```cpp
try {
    auto id = clpkc::make_id_from_ascii("pile-001");
    auto sk = clpkc::compose_full_private(d_hex, t_hex);
    if (!clpkc::verify_keypair_consistency(sk, w_hex, ppub_hex, id)) {
        // 密钥对不自洽 —— 不要落盘，重新开通
    }
} catch (const clpkc::Error& e) {
    // e.what() 记日志
}
```

## 线程安全

所有函数**无全局状态**，内部每次调用自建 OpenSSL 上下文，可多线程并发调用。
随机数依赖 OpenSSL `RAND_bytes`（其自身线程安全）。

## 典型调用顺序（仅供参考，流程编排由集成方实现）

```
开通(仅首次)：
  generate_keypair()                        → (d_B, U_B)，U_B 发给云
  [收到 KGC 下发的 W, cipher, Ppub]
  sm2_decrypt(d_B, cipher)                  → t_B
  compose_full_private(d_B, t_B)            → SK_B
  verify_keypair_consistency(SK_B, W, Ppub, ID32)   → 必须为 true 才落盘

会话(每次)：
  generate_keypair()                        → (b, R_B) 临时
  random_bytes_hex(16)                      → nonce
  sign_initiator(R_B, ID_B32, W_B, nonce, SK_B)     → sig_B，连同 R_B/nonce 发给云
  [收到云的 W_A, R_A, sig_A]
  reconstruct_full_public(ID_A32, W_A, Ppub)        → PK_A
  verify_responder(R_A, R_B, ID_A32, W_A, nonce, sig_A, PK_A)  → 必须 true
  derive_session_key(b, R_A, R_A, R_B, ID_A32, ID_B32, nonce)  → SK 会话密钥
  session_key_to_sm4(SK)                    → SM4 密钥（前 16 字节）
```

## 测试向量

见 [`kat.md`](kat.md) —— 固定输入 → 期望输出，**已与 Java 云端实现双向交叉验证**。
`make test` 跑全量 KAT（当前 32 项全通过）。

## 目录

```
pile-sdk/
├── clpkc_sdk.h        # 唯一对外头文件
├── clpkc_sdk.cpp      # 实现（仅依赖 OpenSSL）
├── selftest.cpp       # KAT 自检
├── CMakeLists.txt     # 库 + selftest + make test
├── kat.md             # 测试向量 + 交叉验证结论
├── README.md          # 本文件
└── tools/KatGen.java  # 交叉验证工具（用 cloud-service 的 Java 实现产出同一组向量）
```
