# CL-PKC 桩端（主机端）密码学 SDK

国密 **SM2 / SM3 / HMAC-SM3** + 无证书公钥密码学（隐式证书，ECQV/SM2 风格）算法库，供充电桩
（主机端）集成。C++17 + OpenSSL 3.x，编译产出单个静态库，除 OpenSSL 外无第三方依赖。

本文件是**完整的算法规格说明**：按此实现即可与云端互通。配套的固定测试向量见
[`kat.md`](kat.md)，可用于接入后自验。

---

## 1. 范围界定

**本 SDK 提供**：密钥生成、随机数、HMAC-SM3、SM2 解密、SM2 签名/验签、隐式证书的完整公私钥
合成与重建、会话密钥派生、ID 与点的编码辅助。全部是**纯函数、无状态、线程安全**。

**本 SDK 不提供**（由集成方实现）：

| 不提供 | 说明 |
|---|---|
| 存储 / keystore | 私钥、`W`、`Ppub` 如何持久化由主机端决定 |
| 网络通信 | 不含 socket、连接、超时、重连 |
| 报文封装 / 解析 | 不含帧头、长度、校验、序列号、报文类型 |
| 流程编排 | 不含状态机、重试、失败回退 |
| 时间戳 / 会话管理 | 不含时间戳、会话生命周期 |

SDK 只回答"这段字节的密码学结果是什么"。

---

## 2. 构建与集成

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
cd build && make test          # 运行 KAT 自检（等价 ctest）
```

产物：`libclpkc_sdk.a` 与 `clpkc_sdk.h`。集成方只需包含 `clpkc_sdk.h` 并链接
`libclpkc_sdk.a` + OpenSSL 的 `libcrypto`。

环境要求：**OpenSSL 3.0 或更高**（需包含 SM2 与 SM3 算法）、C++17 编译器。

---

## 3. 数据表示总则

| 项 | 规定 |
|---|---|
| **传参形式** | 所有入参与返回值都是 **hex 字符串**。输入大小写均可，**输出一律小写**。 |
| **字节序** | 所有多字节整数与标量一律**大端**。 |
| **曲线** | SM2（`sm2p256v1`，GM/T 0003）。参数见 §4.1。 |
| **曲线点** | **64 字节裸 `X‖Y`**（128 hex），**不含 `04` 前缀**。X、Y 各 32 字节，左侧补 0 至定长。 |
| **标量 / 私钥** | **32 字节**（64 hex），左侧补 0 至定长。 |
| **签名** | **64 字节裸 `r‖s`**（128 hex），r、s 各 32 字节左侧补 0。**不是 DER**。 |
| **ID** | **32 字节**（64 hex）。构造见 §4.2。 |
| **nonce** | **16 字节**（32 hex）。 |
| **SM2 密文** | C1C3C2 原始拼接，**129 字节**（258 hex）。 |
| **HMAC-SM3 输出** | **32 字节**（64 hex）。 |

### 唯一需要牢记的规则

> **所有进入哈希 / 签名的字段，一律使用「hex 解码后的原始字节」，绝不使用 hex 文本本身。**

hex 只是本 SDK 接口的传参形式。例如 `nonce_hex` 传入 32 个字符，参与 transcript、会话密钥
派生和 HMAC 计算的都是解码后的那 **16 个字节**，而不是那 32 个字符。

进哈希时各字段的字节数：曲线点 **64**、ID **32**、nonce **16**、`Sx` **32**、签名 r/s 各 **32**。

---

## 4. 算法规格

### 4.1 曲线参数（SM2，`sm2p256v1`）

计算 `HA` 与 SM2 的 `ZA` 都会用到 `a`、`b`、`Gx`、`Gy`，均按 32 字节大端取用：

```
p  = FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
a  = FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
b  = 28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
Gx = 32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
Gy = BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
n  = FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
```

### 4.2 ID 构造

ID 固定 **32 字节**。两端各用一条构造路径：

**桩（主机）ID_B —— `make_id_from_bcd`**

`ID_B = 7 字节 BCD 主机编号 ‖ 25 字节 0x00`

主机编号是**十进制数字串**，长度 1..14 位。不足 14 位时**在左侧补 `'0'`** 补足 14 位
（保持数值不变），再每 2 个十进制位压成 1 字节 BCD（高半字节为前一位数字），得 7 字节。

```
主机编号 "1"（等价于 "00000000000001"）
  → 左补零：00000000000001
  → BCD ：  00 00 00 00 00 00 01
  → ID_B ： 00 00 00 00 00 00 01 | 00 00 00 ... 00   （后 25 字节全 0x00）
  → hex  ： 0000000000000100000000000000000000000000000000000000000000000000
```

**云 ID_A —— `make_id_from_ascii`**

`ID_A = 域名的 ASCII 字节 ‖ 0x00 补齐到 32 字节`

```
域名 "cloud.example.com"（17 字节）
  → ASCII：63 6c 6f 75 64 2e 65 78 61 6d 70 6c 65 2e 63 6f 6d
            c  l  o  u  d  .  e  x  a  m  p  l  e  .  c  o  m
  → ID_A ：上述 17 字节 | 00 × 15
  → hex  ：636c6f75642e6578616d706c652e636f6d000000000000000000000000000000
```

同一个 32 字节 ID 用于 **HA、SM2 的 ZA、transcript、会话密钥派生** 四处，不做任何变形。
因 ID 恒为 32 字节，SM2 的 **ENTL 恒为 `0x0100`**（256 bit，大端两字节）。

### 4.3 隐式证书：完整密钥的合成与重建

KGC 为标识 `ID` 颁发「声明公钥 `W`」与「部分私钥密文」。设本机私钥为 `d`（即 `u_B`）：

```
t   = SM2_Decrypt(d, 部分私钥密文)                 // 32 字节标量
SK  = (d + t) mod n                                // 完整私钥，32 字节

HA  = SM3( 0x0100 ‖ ID(32) ‖ a ‖ b ‖ Gx ‖ Gy ‖ Ppub.x ‖ Ppub.y )    // 32 字节
λ   = SM3( W.x ‖ W.y ‖ HA )                        // 32 字节，按大端无符号整数用作标量
PK  = W + λ·Ppub                                   // 完整公钥（曲线点）
```

其中 `a`/`b`/`Gx`/`Gy` 见 §4.1，`Ppub.x`/`Ppub.y`/`W.x`/`W.y` 均为 32 字节大端。
`λ` 直接以 256 位无符号整数用于点乘（点乘本身按群阶归约，是否显式 `mod n` 不影响结果）。

自洽关系：`SK·G == PK`。`verify_keypair_consistency` 即校验此式。

### 4.4 SM2 解密（部分私钥密文）

密文为 **C1C3C2 原始拼接**：

```
C1(65 字节，含 04 前缀) ‖ C3(32 字节) ‖ C2(明文等长)
```

部分私钥明文为 32 字节，故密文共 **129 字节**（258 hex）。解密按 GM/T 0003：
`S = d·C1`，取 `S` 的 `x2‖y2`；`t = KDF(x2‖y2, len(C2))`，其中 KDF 的计数器从 **1** 开始、
每轮取 `SM3(x2‖y2‖ct_be32)`；明文 `M = C2 XOR t`；最后校验 `C3 == SM3(x2 ‖ M ‖ y2)`，
不符即解密失败。

（C1 的长度由其首字节决定：`04` 为非压缩共 65 字节，`02`/`03` 为压缩共 33 字节；
本协议使用非压缩形式。）

### 4.5 SM2 签名与两段 transcript

签名对象是 transcript，字段**按顺序直接拼接，无长度前缀、无分隔符**，各字段均为原始字节：

```
发起方（主机）transcript = R_B(64) ‖ ID_B(32) ‖ W_B(64) ‖ nonce(16)      共 176 字节
响应方（云）  transcript = R_A(64) ‖ R_B(64) ‖ ID_A(32) ‖ W_A(64) ‖ nonce(16)  共 240 字节
```

对该 transcript 做标准 SM2 数字签名（GM/T 0003）：以 **32 字节 ID** 作为 ZA 的用户标识
（因而 ENTL = `0x0100`），`ZA = SM3(ENTL ‖ ID ‖ a ‖ b ‖ Gx ‖ Gy ‖ PK.x ‖ PK.y)`，
`e = SM3(ZA ‖ transcript)`，签名结果取 **裸 `r‖s`，各 32 字节大端，共 64 字节**。

SM2 签名包含随机数 `k`，因此**相同输入每次签出的值不同，这是正常的**；判定依据是验签结果。

### 4.6 会话密钥与 SM4 密钥

```
Sx = ( 本方临时私钥 × 对端临时公钥 ) 的 X 坐标，32 字节
SK = SM3( Sx(32) ‖ R_A(64) ‖ R_B(64) ‖ ID_A(32) ‖ ID_B(32) ‖ nonce(16) )   共 240 字节输入
```

**单次 SM3**，无计数器、无迭代，输出 **32 字节**会话密钥。

**SM4 密钥 = 会话密钥 SK 的前 16 字节。**

双方各自用自己的临时私钥与对方的临时公钥计算，得到相同的 `Sx`，因而得到相同的 `SK`。

### 4.7 HMAC-SM3

标准 HMAC（RFC 2104）以 SM3 为底层哈希，输出 **32 字节**。密钥与数据均为原始字节
（接口上传 hex，内部解码）。握手挑战值 `random_A` / `random_B` 各 **16 字节**，
参与 HMAC 的是这 16 个原始字节。

---

## 5. API 参考

所有函数位于命名空间 `clpkc`，声明在 `clpkc_sdk.h`。
下表中"长度"列给出 hex 字符数与对应字节数。

### 5.1 密钥与随机数

```cpp
struct KeyMaterial {
    std::string secret_hex;  // 私钥 d：64 hex / 32 字节
    std::string public_hex;  // 公钥 x‖y：128 hex / 64 字节
};
KeyMaterial generate_static_key();
```
生成一对 SM2 密钥，私钥取自 `[1, n-1]` 的密码学安全随机数，公钥 `= d·G`。
长期密钥 `(d_B, U_B)` 与每次会话的临时密钥 `(b, R_B)` 都用此函数生成。
**错误**：内部随机数或运算失败抛 `clpkc::Error`。

```cpp
std::string random_bytes_hex(int n_bytes);
```
| 参数 | 要求 |
|---|---|
| `n_bytes` | 正整数（> 0）。 |

返回 `2 * n_bytes` 个 hex 字符。用于生成 nonce（传 16）与 `random_A`/`random_B`（传 16）。
**错误**：`n_bytes <= 0` 或 CSPRNG 失败抛 `clpkc::Error`。

### 5.2 HMAC-SM3

```cpp
std::string hmac_sm3_hex(const std::string& key_hex, const std::string& data_hex);
```
| 参数 | 长度 | 说明 |
|---|---|---|
| `key_hex` | 任意偶数个 hex 字符 | 预共享密钥，本协议为 32 hex / 16 字节 |
| `data_hex` | 任意偶数个 hex 字符 | 被认证数据，本协议为 32 hex / 16 字节的随机挑战 |

返回 **64 hex / 32 字节**。两个入参都先 hex 解码再计算。
**错误**：hex 非法（奇数长度或非 hex 字符）抛 `clpkc::Error`。

```cpp
bool hmac_sm3_verify(const std::string& key_hex, const std::string& data_hex,
                     const std::string& expected_mac_hex);
```
以**常量时间**比较计算值与 `expected_mac_hex`，防时序侧信道。
校验对端 MAC **必须**用本函数，不要自行用 `==` 比较字符串。
**错误**：**不抛异常**。入参非法或不匹配一律返回 `false`。

### 5.3 隐式证书

```cpp
std::string sm2_decrypt(const std::string& d_hex, const std::string& cipher_hex);
```
| 参数 | 长度 | 说明 |
|---|---|---|
| `d_hex` | 64 hex / 32 字节 | 本机私钥 `u_B` |
| `cipher_hex` | 258 hex / 129 字节 | 部分私钥密文，C1C3C2，C1 含 `04` |

返回明文 `t` 的 hex（本协议为 64 hex / 32 字节）。单独暴露此函数，便于开通失败时区分是
"解密失败"还是"合成失败"。
**错误**：`d_hex` 长度不符、hex 非法、C1 点格式非法或不在曲线上、密文长度不足、
C3 校验不通过 → 抛 `clpkc::Error`。

```cpp
std::string compose_full_private(const std::string& secret_hex,
                                 const std::string& encrypted_partial_hex);
```
| 参数 | 长度 | 说明 |
|---|---|---|
| `secret_hex` | 64 hex / 32 字节 | 本机私钥 `u_B` |
| `encrypted_partial_hex` | 258 hex / 129 字节 | KGC 下发的部分私钥**密文** |

内部先用 `secret_hex` 对密文做 SM2 解密得到 `t`，再返回完整私钥
`SK = (d + t) mod n`，**64 hex / 32 字节**。若只想单独解密不合成，用 `sm2_decrypt`。
**错误**：长度不符、hex 非法、C1 格式非法、C3 校验不过 → 抛 `clpkc::Error`。

```cpp
std::string reconstruct_full_public(const std::string& id_hex,
                                    const std::string& claimed_public_hex,
                                    const std::string& master_public_hex);
```
| 参数 | 长度 | 说明 |
|---|---|---|
| `id_hex` | 64 hex / 32 字节 | 被重建方的 ID（见 §4.2） |
| `claimed_public_hex` | 128 hex / 64 字节 | 被重建方的声明公钥 `W`，裸 `X‖Y` |
| `master_public_hex` | 128 hex / 64 字节 | KGC 主公钥 `Ppub`，裸 `X‖Y` |

按 §4.3 计算并返回完整公钥 `PK`，**128 hex / 64 字节**裸 `X‖Y`。
**错误**：长度不符、hex 非法、点不在 SM2 曲线上 → 抛 `clpkc::Error`。

```cpp
bool verify_keypair_consistency(const std::string& full_private_hex,
                                const std::string& claimed_public_hex,
                                const std::string& master_public_hex,
                                const std::string& id_hex);
```
| 参数 | 长度 | 说明 |
|---|---|---|
| `full_private_hex` | 64 hex / 32 字节 | 完整私钥 |
| `claimed_public_hex` | 128 hex / 64 字节 | 自己的声明公钥 `W` |
| `master_public_hex` | 128 hex / 64 字节 | KGC 主公钥 `Ppub` |
| `id_hex` | 64 hex / 32 字节 | 自己的 ID |

校验 `SK·G == W + λ·Ppub`。**开通流程落盘前应调用一次**，确认拿到的密钥材料自洽。
**错误**：**不抛异常**。入参非法或不自洽一律返回 `false`。

> 注意本函数的参数顺序是 `(full_private, claimed_public, master_public, id)`，
> 与 `reconstruct_full_public` 的 `(id, claimed_public, master_public)` 不同，勿混淆。

### 5.4 签名与验签

```cpp
std::string sign_initiator(const std::string& r_pile_hex, const std::string& id,
                           const std::string& w_hex, const std::string& nonce,
                           const std::string& full_private_hex);
```
| 参数 | 长度 | 说明 |
|---|---|---|
| `r_pile_hex` | 128 hex / 64 字节 | 自己的临时公钥 `R_B`，裸 `X‖Y` |
| `id` | 64 hex / 32 字节 | 自己的 ID_B |
| `w_hex` | 128 hex / 64 字节 | 自己的声明公钥 `W_B`，裸 `X‖Y` |
| `nonce` | 32 hex / 16 字节 | 本次会话 nonce |
| `full_private_hex` | 64 hex / 32 字节 | 自己的完整私钥 |

对发起方 transcript（§4.5）签名，返回 **128 hex / 64 字节**裸 `r‖s`。
**错误**：任一入参长度不符、hex 非法、点不在曲线上 → 抛 `clpkc::Error`。

```cpp
bool verify_responder(const std::string& r_a_hex, const std::string& r_b_hex,
                      const std::string& id, const std::string& w_hex,
                      const std::string& nonce, const std::string& sig_raw_hex,
                      const std::string& full_public_hex);
```
| 参数 | 长度 | 说明 |
|---|---|---|
| `r_a_hex` | 128 hex / 64 字节 | 对端（云）临时公钥 `R_A` |
| `r_b_hex` | 128 hex / 64 字节 | 自己的临时公钥 `R_B` |
| `id` | 64 hex / 32 字节 | 对端 ID_A |
| `w_hex` | 128 hex / 64 字节 | 对端声明公钥 `W_A` |
| `nonce` | 32 hex / 16 字节 | 本次会话 nonce |
| `sig_raw_hex` | 128 hex / 64 字节 | 对端签名，裸 `r‖s` |
| `full_public_hex` | 128 hex / 64 字节 | 对端完整公钥，由 `reconstruct_full_public` 得到 |

校验响应方 transcript（§4.5）上的签名。
**错误**：**不抛异常**。签名不匹配、入参长度不符、hex 非法、点非法一律返回 `false`。

```cpp
bool verify_initiator(const std::string& r_pile_hex, const std::string& id,
                      const std::string& w_hex, const std::string& nonce,
                      const std::string& sig_raw_hex, const std::string& full_public_hex);
```
与 `sign_initiator` 配对的验签函数，参数含义同上，供集成方离线自检与联调定位使用。
**错误**：同 `verify_responder`，不抛异常，一律返回 `bool`。

### 5.5 会话密钥

```cpp
std::string derive_session_key(const std::string& eph_secret_hex, const std::string& peer_point_hex,
                               const std::string& ra_hex, const std::string& rb_hex,
                               const std::string& ida_hex, const std::string& idb_hex,
                               const std::string& nonce);
```
| 参数 | 长度 | 说明 |
|---|---|---|
| `eph_secret_hex` | 64 hex / 32 字节 | **自己的**临时私钥。主机端传 `b` |
| `peer_point_hex` | 128 hex / 64 字节 | **对端的**临时公钥。主机端传 `R_A` |
| `ra_hex` | 128 hex / 64 字节 | 云端临时公钥 `R_A`（参与拼接） |
| `rb_hex` | 128 hex / 64 字节 | 桩端临时公钥 `R_B`（参与拼接） |
| `ida_hex` | 64 hex / 32 字节 | 云端 ID_A |
| `idb_hex` | 64 hex / 32 字节 | 桩端 ID_B |
| `nonce` | 32 hex / 16 字节 | 本次会话 nonce |

按 §4.6 返回 **64 hex / 32 字节**会话密钥。

> 前两个参数决定 ECDH 的计算，后五个参数决定拼接内容。主机端固定传
> `eph_secret_hex = b`、`peer_point_hex = R_A`，而 `ra_hex`/`rb_hex` 无论哪一端都按
> `R_A` 在前、`R_B` 在后传入；`ida_hex`/`idb_hex` 同理固定为云在前、桩在后。

**错误**：任一入参长度不符、hex 非法、点不在曲线上 → 抛 `clpkc::Error`。

```cpp
std::string session_key_to_sm4(const std::string& sk32_hex);
```
| 参数 | 长度 | 说明 |
|---|---|---|
| `sk32_hex` | 64 hex / 32 字节 | 会话密钥 |

返回其**前 16 字节**作为 SM4 密钥，**32 hex / 16 字节**。
**错误**：长度不符或 hex 非法抛 `clpkc::Error`。

### 5.6 编码辅助

```cpp
std::string make_id_from_bcd(const std::string& host_no_decimal);
```
| 参数 | 要求 |
|---|---|
| `host_no_decimal` | 1..14 个字符，**必须全为十进制数字 `0`-`9`** |

**用于构造桩（主机）的 ID_B**。按 §4.2 返回 **64 hex / 32 字节**。
**错误**：为空、超过 14 位、含非十进制字符 → 抛 `clpkc::Error`。

```cpp
std::string make_id_from_ascii(const std::string& ascii);
```
| 参数 | 要求 |
|---|---|
| `ascii` | 长度 ≤ 32 字节的字符串 |

**用于构造云端的 ID_A**（域名）。按 §4.2 返回 **64 hex / 32 字节**。
**错误**：超过 32 字节抛 `clpkc::Error`。

```cpp
std::string point_to_wire(const std::string& point_hex);    // → 128 hex / 64 字节
std::string point_from_wire(const std::string& wire_hex);   // → 130 hex / 65 字节
```
`point_to_wire` 接受 130 hex（65 字节 SEC1 `04‖X‖Y`）或 128 hex（64 字节裸点），
统一输出 64 字节裸点（本协议的线上格式）。
`point_from_wire` 接受 64 字节裸点，输出 65 字节 SEC1 `04‖X‖Y`，供需要 SEC1 输入的库使用。
两者都只做格式转换，**不做曲线校验**。
**错误**：长度不符或 hex 非法抛 `clpkc::Error`。

```cpp
std::string sm3_hex_of_ascii(const std::string& ascii);
```
对 `ascii` 的**原始字节**计算 SM3（不做 hex 解码），返回 **64 hex / 32 字节**。
例：`sm3_hex_of_ascii("abc")` 即标准向量 `SM3("abc")`。

---

## 6. 错误处理

| 情形 | 行为 |
|---|---|
| 入参格式非法（hex 非法、长度不符、点不在曲线上）、内部运算失败 | 抛 **`clpkc::Error`**（派生自 `std::runtime_error`） |
| `verify_responder` / `verify_initiator` / `verify_keypair_consistency` / `hmac_sm3_verify` | **不抛异常**；校验不通过与入参非法都返回 `false` |

设计原则：**长度不符一律立即报错，绝不静默截断或补齐**——静默处理会让两端算出不同结果却
不报错，问题极难定位。

集成建议：对所有非 `verify_*` 的调用包 `try/catch (const clpkc::Error&)`，把 `what()` 写进日志。

```cpp
try {
    auto idB = clpkc::make_id_from_bcd("00000000000001");        // 桩 ID_B
    auto t   = clpkc::sm2_decrypt(d_hex, cipher_hex);
    auto sk  = clpkc::compose_full_private(d_hex, t);
    if (!clpkc::verify_keypair_consistency(sk, w_hex, ppub_hex, idB)) {
        // 密钥材料不自洽：不要落盘，重新执行开通流程
    }
} catch (const clpkc::Error& e) {
    // e.what() 写日志
}
```

## 7. 线程安全

所有函数**无全局状态与静态可变数据**，内部每次调用自建 OpenSSL 上下文，可多线程并发调用。
随机数来自 OpenSSL `RAND_bytes`（其自身线程安全）。

---

## 8. 典型调用顺序

流程编排由集成方实现，此处仅说明各函数在流程中的位置。

```
开通（仅首次）：
  make_id_from_bcd(主机编号)                              → ID_B
  generate_static_key()                                     → (d_B, U_B)；把 U_B 交给云端
  ——— 收到云端下发的 W、部分私钥密文、Ppub ———
  compose_full_private(d_B, 密文)                         → SK_B（内部解密后合成）
  （如需单独定位解密问题：sm2_decrypt(d_B, 密文) → t）
  verify_keypair_consistency(SK_B, W, Ppub, ID_B)        → 必须为 true，才可持久化
  持久化 d_B（或 SK_B）、W、Ppub、ID_B

会话（每次）：
  generate_static_key()                                     → (b, R_B) 临时密钥
  random_bytes_hex(16)                                   → nonce
  sign_initiator(R_B, ID_B, W_B, nonce, SK_B)            → sig_B；把 R_B、nonce、sig_B 交给云端
  ——— 收到云端的 ID_A、W_A、R_A、sig_A ———
  reconstruct_full_public(ID_A, W_A, Ppub)               → PK_A
  verify_responder(R_A, R_B, ID_A, W_A, nonce, sig_A, PK_A)   → 必须为 true，否则中止
  derive_session_key(b, R_A, R_A, R_B, ID_A, ID_B, nonce)     → SK 会话密钥
  session_key_to_sm4(SK)                                 → SM4 密钥（SK 前 16 字节）
```

---

## 9. 字段长度速查

| 字段 | 字节 | hex 字符 |
|---|---|---|
| 曲线点 `U`/`W`/`R_A`/`R_B`/`Ppub`/`PK`（裸 `X‖Y`） | 64 | 128 |
| 标量 `d`/`t`/`SK`/临时私钥 | 32 | 64 |
| `ID_A` / `ID_B` | 32 | 64 |
| `nonce` | 16 | 32 |
| `random_A` / `random_B` | 16 | 32 |
| 预共享密钥 | 16 | 32 |
| SM2 签名（裸 `r‖s`） | 64 | 128 |
| HMAC-SM3 输出 | 32 | 64 |
| SM2 密文（部分私钥，C1C3C2） | 129 | 258 |
| 会话密钥 `SK` | 32 | 64 |
| SM4 密钥（`SK` 前 16 字节） | 16 | 32 |
| `HA` / `λ` / SM3 输出 | 32 | 64 |
| 发起方 transcript | 176 | — |
| 响应方 transcript | 240 | — |
| 会话密钥 SM3 输入 | 240 | — |

---

## 10. 测试向量

[`kat.md`](kat.md) 给出固定输入与期望输出，覆盖本文件描述的每个算法环节。
`make test`（或直接运行 `clpkc_selftest`）会跑全部向量，**当前 35 项全部通过**。

## 11. 目录

```
pile-sdk/
├── clpkc_sdk.h        # 唯一对外头文件
├── clpkc_sdk.cpp      # 实现（仅依赖 OpenSSL）
├── selftest.cpp       # KAT 自检程序
├── CMakeLists.txt     # 静态库 + selftest + make test
├── kat.md             # 测试向量
├── README.md          # 本文件
└── tools/KatGen.java  # 用 Java 实现产出同一组向量的对照工具
```
