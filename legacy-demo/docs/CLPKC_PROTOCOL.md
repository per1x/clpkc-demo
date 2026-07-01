# CL-PKC Demo Protocol

## 曲线与编码

- 曲线: `secp256r1`
- 哈希: `SHA-256`
- HMAC: `HmacSHA256`
- EC 点编码: SEC1 非压缩格式, `04 || X(32B) || Y(32B)`
- 标量编码: 32 字节无符号大端十六进制

---

## 协议流程总览

```
┌──────┐                              ┌───────┐                              ┌─────┐
│ Pile │                              │ Cloud │                              │ KGC │
│(设备)│                              │(云端) │                              │(中心)│
└──┬───┘                              └───┬───┘                              └──┬──┘
   │                                      │                                      │
   │  ① connect (WebSocket)               │                                      │
   │─────────────────────────────────────>│                                      │
   │                                      │                                      │
   │  ② challenge (nonce)                 │                                      │
   │<─────────────────────────────────────│                                      │
   │                                      │                                      │
   │  ③ hmac (ID || P_i || HMAC(nonce))   │                                      │
   │─────────────────────────────────────>│                                      │
   │                                      │                                      │
   │  ④ auth_ok (ID || P_c || Y_c)        │                                      │
   │<─────────────────────────────────────│                                      │
   │                                      │                                      │
   │  ⑤ partial_key_request (ID || P_i)   │                                      │
   │─────────────────────────────────────>│                                      │
   │                                      │                                      │
   │                                      │  ⑥ forward request (ID || P_i)       │
   │                                      │─────────────────────────────────────>│
   │                                      │                                      │
   │                                      │  ⑦ encrypted partial key (ECIES)     │
   │                                      │<─────────────────────────────────────│
   │                                      │                                      │
   │  ⑧ partial_key_response (ECIES)      │                                      │
   │<─────────────────────────────────────│                                      │
   │                                      │                                      │
   │  ⑨ ka_request (P_i || Y_i || RA || SIG_A)                                  │
   │─────────────────────────────────────>│                                      │
   │                                      │                                      │
   │  ⑩ ka_response (P_c || Y_c || RB || SIG_B)                                 │
   │<─────────────────────────────────────│                                      │
   │                                      │                                      │
   │  ═══ 双方独立计算会话密钥 SK ═══       │                                      │
   │  SK = SHA256(x(ECDH) || RA || RB     │                                      │
   │            || ID_A || ID_B || T_A || T_B)                                   │
   │                                      │                                      │
```

---

## 各步骤详细说明

### 步骤 ①②③: HMAC 挑战-响应认证

| 方向 | 消息 | 说明 |
|------|------|------|
| ① Pile → Cloud | WebSocket 连接 | Pile 作为客户端主动发起连接 |
| ② Cloud → Pile | `challenge(nonce)` | Cloud 生成随机 nonce，发送给 Pile |
| ③ Pile → Cloud | `hmac(id, P_i, mac)` | Pile 用预共享密钥计算 HMAC 并返回 |

**密码学操作**: Pile 使用预共享密钥 `K_shared` 对 nonce 计算 HMAC-SHA256: `mac = HMAC(K_shared, nonce)`。

**必要性**: 在 Pile 注册阶段，Pile 和 Cloud 已通过带外方式共享了密钥 `K_shared`。HMAC 挑战-响应用于验证 Pile 确实持有该共享密钥，是 Pile 身份的第一道防线。

**安全属性**: 提供 **实体认证**。nonce 保证新鲜性（防重放攻击）；HMAC 保证只有持有 `K_shared` 的合法设备才能通过验证；无需传输共享密钥本身，防止密钥泄露。

**传输内容**:
- `id`: Pile 的设备标识
- `publicKey` (`P_i`): Pile 的自选公钥 `P_i = x_i·G`（首次向 Cloud 公开）
- `mac`: HMAC-SHA256 计算结果

---

### 步骤 ④: 云端身份确认

| 方向 | 消息 | 说明 |
|------|------|------|
| ④ Cloud → Pile | `auth_ok(id, P_c, Y_c)` | Cloud 确认认证通过，返回自身公钥信息 |

**密码学操作**: 无新增密码学计算。但 `Y_c = d_c·G` 是 Cloud 的派生公钥分量。

**必要性**: Pile 需要知道 Cloud 的完整公钥 `PK_c = P_c + Y_c`，以便后续验证 Cloud 的 Schnorr 签名。将 `P_c` 和 `Y_c` 分开传输，使得 Pile 能够清晰地区分"自选密钥分量"和"KGC 派生分量"。

**安全属性**: 提供 **公钥透明性**。Pile 可以独立计算 `PK_c = P_c + Y_c` 并验证后续签名。

---

### 步骤 ⑤⑥⑦⑧: 部分私钥请求与分发

| 方向 | 消息 | 说明 |
|------|------|------|
| ⑤ Pile → Cloud | `partial_key_request(id, P_i)` | Pile 请求 KGC 为其生成部分私钥 |
| ⑥ Cloud → KGC | 转发请求 | Cloud 将请求代理转发给 KGC (HTTPS) |
| ⑦ KGC → Cloud | ECIES 密文 | KGC 用 ECIES 加密部分私钥点 `D_i` |
| ⑧ Cloud → Pile | ECIES 密文 | Cloud 将密文转发给 Pile |

**密码学操作（KGC 端）**:

1. 验证请求者身份 `(ID_i, P_i)`
2. 计算 `Q_i = H1(ID_i || P_i)` — 将身份和公钥哈希到曲线上的点
3. 计算 `D_i = s · Q_i` — 部分私钥（**点**，非标量！）
4. 用 ECIES 加密 `D_i`: 生成临时密钥对 `(r, R=rG)`，计算共享点 `S = r·P_i`，AES-256-GCM 加密

**必要性**: 

- Pile 需要 `D_i` 来构造完整私钥 `sk_i = x_i + d_i`，其中 `d_i = H2(D_i.x || D_i.y) mod n`。
- 使用 ECIES 加密确保只有 Pile（持有 `x_i` 的人）能解密。因为要解密必须计算 `S = x_i·R = r·P_i`，这需要知道 `x_i`。

**安全属性**: 

- **防窃听**: 即使攻击者截获密文，不知道 `x_i` 就无法解密（基于 ECDH 密钥协商）。
- **防 KGC 伪造**: KGC 无法在不经 Pile 同意的情况下为 Pile 颁发部分私钥，因为只有 Pile 能解密。
- **防中间人**: ECIES 的 AES-256-GCM 认证标签确保密文完整性。

**ECIES 密文格式**:
```
R(65B) || nonce(12B) || ciphertext(65B) || tag(16B) = 158 字节 = 316 hex 字符
```

---

### 步骤 ⑨⑩: 签名 ECDH 密钥协商

| 方向 | 消息 | 说明 |
|------|------|------|
| ⑨ Pile → Cloud | `ka_request(P_i, Y_i, RA, t, sig)` | Pile 发送密钥协商请求 |
| ⑩ Cloud → Pile | `ka_response(P_c, Y_c, RB, t, sig)` | Cloud 回复密钥协商响应 |

**密码学操作（以 Pile 发起为例）**:

1. 生成临时 ECDH 密钥对 `(r_A_e, RA = r_A_e·G)`
2. 构造签名记录: `transcript = ka_request || P_i || Y_i || RA || t`
3. 生成 Schnorr 签名: `(R_sig = k·G, s = k + e·sk_i mod n)` 其中 `e = SHA256(R_sig || transcript)`
4. 发送消息包含 `RA` (临时公钥) 和 `sig` (Schnorr 签名)

**验证方操作**:

1. 计算发起方完整公钥: `PK_i = P_i + Y_i`
2. 重建 transcript 并提取 `e = SHA256(R_sig || transcript)`
3. 验证 Schnorr: `s·G == R_sig + e·PK_i`

**必要性**: 

- ECDH 临时密钥对 (`RA`, `RB`) 用于生成前向安全的会话密钥（即使长期私钥泄露，历史会话密钥仍安全）。
- Schnorr 签名防止中间人攻击：攻击者无法伪造签名（没有 `sk_i`）。
- `derivedPublic` 字段已包含在 ④⑨⑩ 消息中，确保双方都能计算完整公钥用于签名验证。

**安全属性**: 

- **前向安全性**: 临时密钥对 `(r_A_e, RA)` 在会话结束后销毁，即使长期密钥泄露，历史会话密钥不受影响。
- **双向认证**: 双方都需提供 Schnorr 签名，防止任何一方被冒充。
- **抗重放**: 时间戳 `t` 防止旧消息被重放。

---

### 会话密钥派生

双方各自独立计算:

```
SK = SHA256(
    x(ECDH_shared) ||  — ECDH 共享点的 X 坐标 (32B)
    RA              ||  — Pile 的临时公钥 (SEC1 点)
    RB              ||  — Cloud 的临时公钥 (SEC1 点)
    ID_A            ||  — 发起方标识
    ID_B            ||  — 响应方标识
    T_A             ||  — 发起方时间戳
    T_B                — 响应方时间戳
)
```

其中:
- Pile 计算: `ECDH_shared = r_A_e · RB`
- Cloud 计算: `ECDH_shared = r_B_e · RA`
- 两者等价: `r_A_e · RB = r_A_e · r_B_e · G = r_B_e · RA`

将双方的身份、临时公钥、时间戳全部纳入哈希，确保 **会话密钥绑定到特定会话和特定对端**。

---

## 无证书密钥构造（基于点）

本 Demo 实现了一种 **有界无证书方案**，其中部分私钥是一个椭圆曲线点，受 ECDLP 保护：

- KGC 主密钥: `s`（标量）
- KGC 主公钥: `Ppub = s·G`（点）
- 用户秘密值: `x_i`（标量，用户自选）
- 用户公钥: `P_i = x_i·G`（点）

### 密钥派生全景图

```
                        KGC 密钥生成机构
                             │
                    主密钥 s (标量, 保密)
                    主公钥 Ppub = s·G (点, 公开)
                             │
                ┌────────────┼────────────┐
                │            │            │
                ▼            │            ▼
          用户 A                      用户 B
          │                            │
          │① 自选秘密值                 │
          │  x_A ← Z_n*               x_B ← Z_n*
          │  P_A = x_A·G              P_B = x_B·G
          │                            │
          │② 身份-公钥绑定             │
          │  Q_A = H1(ID_A || P_A)    Q_B = H1(ID_B || P_B)
          │  (哈希到曲线 → 点)         (哈希到曲线 → 点)
          │                            │
          │③ KGC 生成部分私钥          │
          │  D_A = s · Q_A            D_B = s · Q_B
          │  (椭圆曲线点乘 → 点)       (椭圆曲线点乘 → 点)
          │  ◄── ECIES 加密传输 ──►    ◄── ECIES 加密传输 ──►
          │                            │
          │④ 用户端标量提取            │
          │  d_A = H2(D_A.x||D_A.y)   d_B = H2(D_B.x||D_B.y)
          │       mod n (标量)              mod n (标量)
          │                            │
          │⑤ 完整私钥合成              │
          │  sk_A = x_A + d_A mod n   sk_B = x_B + d_B mod n
          │                            │
          │⑥ 派生公钥分量              │
          │  Y_A = d_A·G              Y_B = d_B·G
          │                            │
          │⑦ 完整公钥合成              │
          │  PK_A = P_A + Y_A         PK_B = P_B + Y_B
          │                            │
          │⑧ 一致性验证               │
          │  PK_A = (x_A+d_A)·G       PK_B = (x_B+d_B)·G
          │       = sk_A·G                 = sk_B·G
```

**关键设计要点**:

| 步骤 | 操作 | 为什么这样设计 |
|------|------|---------------|
| ① 自选秘密值 | `x_i ← Z_n*`, `P_i = x_i·G` | 用户自己生成密钥分量，KGC 不知 `x_i`，实现**无密钥托管** |
| ② H1 哈希到曲线 | `Q_i = H1(ID_i \|\| P_i)` 映射到曲线点 | 将身份与公钥**绑定**，抵抗密钥替换攻击 |
| ③ 部分私钥 | `D_i = s · Q_i`（**点**，非标量） | ECDLP 保护主密钥 `s`；攻击者无法从 `D_i` 反推 `s` |
| ④ H2 标量提取 | `d_i = H2(D_i.x\|\|D_i.y) mod n` | 将点转换为标量；H2 提供单向性 |
| ⑤ 完整私钥 | `sk_i = x_i + d_i mod n` | 结合用户分量和 KGC 分量，**双方缺一不可** |
| ⑥ 派生公钥 | `Y_i = d_i·G` | 允许对方独立计算完整公钥 `PK_i = P_i + Y_i` |
| ⑧ 一致性 | `PK_i = sk_i·G` | 保证公私钥对的数学正确性 |

---

### 哈希到曲线 (H1)

`Q_i = H1(ID_i || P_i)` — 将 (身份 || 公钥) 映射到 secp256r1 曲线上的点，使用 try-and-increment 方法:

1. 计算 `digest = SHA256(ID_i || P_i || counter)`，其中 counter 从 0 开始
2. 取 digest 的前 32 字节作为 x 坐标: `x = digest mod p`
3. 求解 `y² = x³ + ax + b (mod p)`，使用 `y = rhs^((p+1)/4) mod p`（secp256r1 的 p ≡ 3 mod 4，此公式有效）
4. 如果 `y² ≠ rhs`，递增 counter 并重试
5. 选择 y 的 LSB 与 digest 最后一字节的 LSB 匹配的点

**设计说明**: try-and-increment 是一种经典的哈希到曲线方法。它简单、确定性强，且对于 secp256r1 平均仅需约 2 次迭代即可找到有效点。

---

### 部分私钥生成（KGC 端）

`D_i = s · Q_i` — 曲线上的**点**，ECDLP 保护 `s` 不可恢复。

**与不安全标量构造的对比**:

| 方案 | 部分私钥 | 主密钥泄露风险 |
|------|---------|---------------|
| ❌ 不安全标量方案 | `d_i = s · h_i mod n` | `s = d_i · h_i⁻¹ mod n` — 一个合法用户即可恢复主密钥 |
| ✅ 本方案（点方案） | `D_i = s · Q_i`（点） | 需要求解 ECDLP 才能从 `(Q_i, D_i)` 恢复 `s` — 计算上不可行 |

由于 `D_i` 是一个点而非标量，即使攻击者同时掌握 `D_i` 和 `Q_i`，恢复 `s` 等价于求解椭圆曲线离散对数问题。

---

### 完整密钥派生（用户端）

收到并 ECIES 解密 `D_i` 后:

1. `d_i = H2(D_i) = SHA256(x(D_i) || y(D_i)) mod n` — 提取标量
2. 完整私钥: `sk_i = (x_i + d_i) mod n`
3. 派生公钥分量: `Y_i = d_i · G`
4. 完整公钥: `PK_i = P_i + Y_i`

密钥对一致性验证:

`PK_i = P_i + d_i·G = (x_i + d_i)·G = sk_i·G`  ✓

**为什么先点后标量**: D_i 是点而非标量的设计是整个方案安全性的核心。在传输阶段，D_i 作为点受到 ECDLP 保护；在密钥合成阶段，通过 H2 将其转换为标量 `d_i` 用于模加运算。这实现了"传输安全"与"计算便利"的平衡。

---

### 签名方案 (Schnorr)

**签名生成**:
1. 选择随机数 `k ← Z_n*`
2. 计算 `R = k·G`
3. 计算挑战: `e = SHA256(R || transcript)`
4. 计算签名: `s = k + e·sk_i mod n`
5. 输出签名 `(R, s)`

**签名验证**:
1. 计算挑战: `e = SHA256(R || transcript)`
2. 验证: `s·G == R + e·PK_i`

**正确性证明**:
```
s·G = (k + e·sk_i)·G = k·G + e·sk_i·G = R + e·PK_i
```

**为什么选择 Schnorr**:
- 签名短小（64 字节: R.x(32B) + s(32B)），适合带宽受限场景
- 线性特性天然支持无证书方案中的密钥聚合验证
- 无求逆运算，签名速度优于 ECDSA
- 可证明安全性基于离散对数假设

---

## Socket 消息格式

消息采用 UTF-8 JSON，每行一个对象（换行符分隔的 JSON）。

### 消息格式总览

#### ② Cloud → Pile: challenge

| 字段 | 类型 | 长度 | 描述 |
|------|------|------|------|
| `type` | string | — | 固定值 `"challenge"` |
| `nonce` | hex string | 64 | CSPRNG 生成的 32 字节随机数 |

```json
{"type":"challenge","nonce":"<hex>"}
```

#### ③ Pile → Cloud: hmac

| 字段 | 类型 | 长度 | 描述 |
|------|------|------|------|
| `type` | string | — | 固定值 `"hmac"` |
| `id` | string | — | Pile 设备标识符 |
| `publicKey` | hex string | 130 | Pile 自选公钥 `P_i`（SEC1 非压缩, 65B） |
| `mac` | hex string | 64 | `HMAC-SHA256(K_shared, nonce)` |

```json
{"type":"hmac","id":"pile-001","publicKey":"<hex>","mac":"<hex>"}
```

#### ④ Cloud → Pile: auth_ok

| 字段 | 类型 | 长度 | 描述 |
|------|------|------|------|
| `type` | string | — | 固定值 `"auth_ok"` |
| `id` | string | — | Cloud 标识符 |
| `publicKey` | hex string | 130 | Cloud 自选公钥 `P_c`（SEC1 非压缩） |
| `derivedPublic` | hex string | 130 | Cloud 派生公钥 `Y_c = d_c·G`（SEC1 非压缩） |

```json
{"type":"auth_ok","id":"cloud-001","publicKey":"<hex>","derivedPublic":"<hex>"}
```

Cloud 同时返回其静态公钥 `P_c` 和派生公钥 `Y_c`，Pile 可据此计算 Cloud 的完整公钥 `PK_c = P_c + Y_c`。

#### ⑤ Pile → Cloud: partial_key_request

| 字段 | 类型 | 长度 | 描述 |
|------|------|------|------|
| `type` | string | — | 固定值 `"partial_key_request"` |
| `id` | string | — | Pile 设备标识符 |
| `publicKey` | hex string | 130 | Pile 公钥 `P_i`（KGC 需以此加密 `D_i`） |

```json
{"type":"partial_key_request","id":"pile-001","publicKey":"<hex>"}
```

#### ⑥ Cloud → KGC (HTTPS): forward request

| 字段 | 类型 | 长度 | 描述 |
|------|------|------|------|
| `id` | string | — | 请求部分私钥的设备标识 |
| `publicKey` | hex string | 130 | 请求者的公钥，KGC 用于 ECIES 加密 |

```json
{"id":"pile-001","publicKey":"<hex>"}
```

#### ⑦⑧ KGC → Cloud → Pile: partial_key_response

| 字段 | 类型 | 长度 | 描述 |
|------|------|------|------|
| `type` | string | — | 固定值 `"partial_key_response"` |
| `curve` | string | — | 曲线名称 `"secp256r1"` |
| `partialPrivate` | hex string | 316 | ECIES 加密的部分私钥点 `D_i` |
| `masterPublicKey` | hex string | 130 | KGC 主公钥 `Ppub = s·G`（SEC1 非压缩） |

```json
{"type":"partial_key_response","curve":"secp256r1","partialPrivate":"<hex>","masterPublicKey":"<hex>"}
```

`partialPrivate` 字段包含经 ECIES 加密的部分私钥**点** `D_i`（65 字节 SEC1 点 → 65 字节明文）。密文格式 (hex):

`R(65B) || nonce(12B) || ciphertext(65B) || tag(16B)` = 316 hex 字符

其中:
- `R` 为临时公钥点（SEC1 非压缩）
- `nonce` 为 AES-256-GCM nonce
- `ciphertext` 为加密后的 `D_i` 点
- `tag` 为 AES-256-GCM 认证标签

**ECIES 加密**（KGC 执行）:
1. 生成临时密钥对 `(r, R = rG)`
2. 计算共享点 `S = r · P_i`，其中 `P_i` 为请求者公钥
3. 派生 AES-256 密钥: `k = SHA256(x(S))`，其中 `x(S)` 为 `S` 的 32 字节 X 坐标
4. 使用密钥 `k` 和随机 12 字节 nonce，以 AES-256-GCM 加密 `D_i`（65 字节 SEC1 点）
5. 输出: `encode(R) || nonce || ciphertext || tag`

**ECIES 解密**（接收方执行）:
1. 从二进制数据中解析 `R`, `nonce`, `ciphertext`, `tag`
2. 计算共享点 `S = x_i · R`
3. 派生 AES-256 密钥: `k = SHA256(x(S))`
4. 以 AES-256-GCM 解密密文，恢复 `D_i`（65 字节 SEC1 点）

#### ⑨ Pile → Cloud: ka_request

| 字段 | 类型 | 长度 | 描述 |
|------|------|------|------|
| `type` | string | — | 固定值 `"ka_request"` |
| `id` | string | — | 发起方标识 |
| `publicKey` | hex string | 130 | Pile 自选公钥 `P_i`（SEC1 非压缩） |
| `derivedPublic` | hex string | 130 | Pile 派生公钥 `Y_i = d_i·G`（SEC1 非压缩） |
| `ra` | hex string | 130 | Pile 临时 ECDH 公钥 `RA`（SEC1 非压缩） |
| `t` | integer | — | Unix 时间戳（秒） |
| `sig` | hex string | 128 | Schnorr 签名: `R.x(32B) || s(32B)` |

```json
{"type":"ka_request","id":"pile-001","publicKey":"<hex>","derivedPublic":"<hex>","ra":"<hex>","t":<ts>,"sig":"<hex>"}
```

Pile 附加其 `derivedPublic` (Y_i)，使 Cloud 能够计算 Pile 的完整公钥 `PK_i = P_i + Y_i` 以验证签名。

#### ⑩ Cloud → Pile: ka_response

| 字段 | 类型 | 长度 | 描述 |
|------|------|------|------|
| `type` | string | — | 固定值 `"ka_response"` |
| `id` | string | — | 响应方标识 |
| `publicKey` | hex string | 130 | Cloud 自选公钥 `P_c`（SEC1 非压缩） |
| `derivedPublic` | hex string | 130 | Cloud 派生公钥 `Y_c = d_c·G`（SEC1 非压缩） |
| `rb` | hex string | 130 | Cloud 临时 ECDH 公钥 `RB`（SEC1 非压缩） |
| `t` | integer | — | Unix 时间戳（秒） |
| `sig` | hex string | 128 | Schnorr 签名: `R.x(32B) || s(32B)` |

```json
{"type":"ka_response","id":"cloud-001","publicKey":"<hex>","derivedPublic":"<hex>","rb":"<hex>","t":<ts>,"sig":"<hex>"}
```

Cloud 同样附加其 `derivedPublic`，供 Pile 验证签名。

---

## 安全属性

### 1. 无密钥托管 (No Key Escrow)

**问题**: 在传统基于身份的密码系统 (IBC) 中，KGC 掌握主密钥并能生成所有用户的完整私钥，因此可以解密所有通信。

**本方案的对策**:

- 用户私钥由两部分组成: `sk_i = x_i + d_i mod n`
  - `x_i`: 用户自行生成并保密的秘密值。**KGC 永远不知道 `x_i`**。
  - `d_i`: KGC 派生的部分私钥（来自 `D_i = s·Q_i`）

- KGC 知道 `s`，可以计算任意用户的 `D_i = s·Q_i`，进而得到 `d_i`。
- 但 KGC **无法**知道用户的 `x_i`，因此无法计算完整私钥 `sk_i`。
- 这意味着 KGC 不能解密用户通信，不能伪造用户签名。

**结论**: 即使 KGC 被完全攻陷，攻击者仍需要每个用户的 `x_i` 才能解密通信或伪造签名。用户自行生成和保管 `x_i`，KGC 不知情。

---

### 2. ECDLP 主密钥保护

**问题**: 在不安全的无证书方案中，部分私钥以标量 `d_i = s · h_i mod n` 形式分发。攻击者获得一个合法用户的 `d_i` 后，可直接计算 `s = d_i · h_i⁻¹ mod n`，从而恢复主密钥并攻陷整个系统。

**本方案的对策**:

- 部分私钥以**点**而非标量形式分发: `D_i = s · Q_i`
- 要从 `(Q_i, D_i)` 恢复 `s`，必须求解: 已知 `Q_i` 和 `D_i = s·Q_i`，求 `s`
- 这就是**椭圆曲线离散对数问题 (ECDLP)**，在 secp256r1 上计算上不可行（~2¹²⁸ 安全级别）

**对比**:

| 攻击场景 | 不安全标量方案 | 本方案（点方案） |
|---------|-------------|-------------|
| 单个合法用户恢复 `s` | `s = d_i · h_i⁻¹ mod n` — 秒级 | 需解 ECDLP — 不可行 |
| 用户串谋恢复 `s` | 仅需 1 人 | 仍需解 ECDLP — 不可行 |
| 安全依赖 | 模逆运算的保密性 | ECDLP 的计算困难性 |

---

### 3. Schnorr 签名认证

**提供的安全属性**:

- **密钥绑定**: 签名使用完整私钥 `sk_i = x_i + d_i`，验证使用完整公钥 `PK_i = P_i + Y_i`。任何一方（用户或 KGC）都不能单独生成有效签名。
- **不可伪造性**: 基于离散对数假设，在随机预言模型下可证明安全。攻击者无法在没有 `sk_i` 的情况下生成有效签名。
- **抗密钥替换攻击**: 签名验证时使用 `PK_i = P_i + Y_i`，其中 `Y_i = d_i·G` 来自 `D_i = s·Q_i` 而 `Q_i = H1(ID_i || P_i)`。攻击者无法用不同的 `P_i'` 生成有效签名，因为 `Q_i` 与 `P_i` 绑定。
- **会话绑定**: 签名覆盖 transcript（包含时间戳、临时公钥等），将签名绑定到特定会话，防止跨会话重放。

---

### 4. ECIES 机密性

**提供的安全属性**:

- **密钥封装**: ECIES 使用 ECDH 为每次部分私钥分发生成独立的对称密钥。即使攻击者截获多次分发，每次使用的密钥都不同。
- **认证加密**: AES-256-GCM 同时提供机密性和完整性。认证标签确保密文未被篡改。
- **仅目标用户可解密**: 加密时使用接收方公钥 `P_i` 计算共享点 `S = r·P_i`。解密需要 `x_i` 来计算 `S = x_i·R`。只有持有 `x_i` 的目标用户能够正确解密。
- **前向安全性（部分私钥层面）**: KGC 每次使用新的临时密钥 `r`，旧分发密文的安全性不依赖于永久密钥。
- **抗选择密文攻击 (IND-CCA2)**: ECIES 的 Encrypt-then-MAC 构造达到 IND-CCA2 安全级别。

**ECIES 安全性总结**:

```
威胁模型:
  攻击者 ──截获──► {R, nonce, ciphertext, tag}
                      │
  攻击者不知道 x_i ──► 无法计算 S = x_i·R
                      │
                      ▼
              无法派生 AES 密钥 → 无法解密 D_i
```

---

### 安全属性总结

| 安全属性 | 实现机制 | 依赖假设 |
|---------|---------|---------|
| 无密钥托管 | `sk_i = x_i + d_i`, KGC 不知 `x_i` | 用户安全保管 `x_i` |
| 主密钥保护 | `D_i = s·Q_i` 是点，非标量 | ECDLP 困难性 |
| 抗密钥替换 | `Q_i = H1(ID_i \|\| P_i)` 绑定身份与公钥 | H1 的抗碰撞性 |
| 实体认证 | HMAC 挑战-响应 + Schnorr 签名 | HMAC 不可伪造性 + DL 假设 |
| 消息机密性 | ECIES 加密部分私钥 | ECDH + AES-256-GCM 安全性 |
| 前向安全性 | 临时 ECDH 密钥对生成会话密钥 | 临时密钥在会话后销毁 |
| 抗重放攻击 | nonce (HMAC 阶段) + 时间戳 (KA 阶段) | 时间戳有效期窗口 |
| 双向认证 | 双方均需提供 Schnorr 签名 | DL 假设 + 双方 `sk_i` 保密 |

---

## 附录: 符号速查

| 符号 | 类型 | 含义 |
|------|------|------|
| `G` | 点 | secp256r1 生成元 |
| `n` | 标量 | secp256r1 的阶 |
| `s` | 标量 | KGC 主密钥（保密） |
| `Ppub` | 点 | KGC 主公钥 `= s·G`（公开） |
| `x_i` | 标量 | 用户 i 自选的秘密值 |
| `P_i` | 点 | 用户 i 的自选公钥 `= x_i·G` |
| `Q_i` | 点 | `H1(ID_i \|\| P_i)`，身份-公钥绑定点 |
| `D_i` | 点 | 部分私钥 `= s·Q_i`（点，ECIES 加密传输） |
| `d_i` | 标量 | `H2(D_i.x \|\| D_i.y) mod n` |
| `Y_i` | 点 | 派生公钥分量 `= d_i·G` |
| `sk_i` | 标量 | 完整私钥 `= x_i + d_i mod n` |
| `PK_i` | 点 | 完整公钥 `= P_i + Y_i = sk_i·G` |
| `K_shared` | 字节串 | Pile-Cloud 预共享密钥（带外分发） |
| `RA / RB` | 点 | 临时 ECDH 公钥（KA 阶段） |
| `SK` | 字节串 | 会话密钥 `= SHA256(...)` |
