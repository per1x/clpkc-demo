# CL-PKC 桩端 SDK —— 测试向量（KAT）

本文件给出**固定输入 → 期望输出**的已知答案测试向量，覆盖 [`README.md`](README.md) 第 4 章
描述的每个算法环节。集成方接入后可据此自验实现是否正确。

这些向量同时由 Java 侧实现（BouncyCastle）产出相同结果，因此按本文件对齐即可与云端互通。

---

## 如何运行

```bash
cd pile-sdk
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
cd build && make test          # 等价：直接运行 ./clpkc_selftest
```

`clpkc_selftest` 会逐项打印 `[PASS]` / `[FAIL]`，并在末尾汇总。全部通过时进程退出码为 `0`，
任一失败为 `1`，可直接接入 CI。**当前 35 项全部通过。**

每组向量下方标注的 `[KAT-n]` 与 selftest 的输出分组一一对应，便于定位失败项。

---

## 1. 输入常量

以下值在本文件中被反复引用。所有值均为 hex 字符串。

### 1.1 标量与随机量

| 名称 | 值 | 说明 |
|---|---|---|
| `ms` | `0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef` | KGC 主私钥（仅用于生成本组向量） |
| `ua_pile` | `1122334455667788990011223344556677889900112233445566778899001122` | 桩本机私钥 `d_B` |
| `ua_cloud` | `2233445566778899001122334455667788990011223344556677889900112233` | 云本机私钥 |
| `eph_b` | `3344556677889900112233445566778899001122334455667788990011223344` | 桩临时私钥 `b` |
| `eph_a` | `4455667788990011223344556677889900112233445566778899001122334455` | 云临时私钥 `a` |
| `nonce` | `0102030405060708090a0b0c0d0e0f10` | 16 字节会话 nonce |
| `psk` | `00112233445566778899aabbccddeeff` | 16 字节预共享密钥 |

### 1.2 身份

| 名称 | 值 |
|---|---|
| 桩主机编号（十进制） | `00000000000001` |
| `ID_B` | `0000000000000100000000000000000000000000000000000000000000000000` |
| 云域名 | `cloud.example.com` |
| `ID_A` | `636c6f75642e6578616d706c652e636f6d000000000000000000000000000000` |

### 1.3 由标量导出的公开量

| 名称 | 值 | 由来 |
|---|---|---|
| `Ppub` | `344081b80805540a38d71d721bd072d8957eae15aeb852e72086ab4c5962b89b5bb8628b9d9c4edd30f341a5a25886c063cff46dc04c7e68f2efb3b58830e0f3` | `ms·G` |
| `R_B` | `d7bddda6449033e3202e9d1633d28584b23624c77f0091c745e5c8c7fc13df8a91e03e64c5646c62deb6f12dd80a699c2c61b95c80a768a991d7e6df292e0a63` | `eph_b·G` |
| `R_A` | `d362a0cb4932a4beba9f1fd22879ffe0e2ffaf65987aaa19b1a4e7d5877be3db844fbdf0065ffcaa35111ccdb9b1321941d907b23f3cf19852fec8b5b4881d22` | `eph_a·G` |

### 1.4 KGC 颁发结果与云端签名

| 名称 | 值 |
|---|---|
| `W_pile` | `c40387e9a0d933cfe840e343ec6df4d227c9901654cdac8186cd1825e4958da5030a5b74e617f483ef688d8b01e6dbd8ae2f6ed102decea8e8b4367f714e6ca9` |
| `cipher_pile`（129 字节） | `04403ca4451e324adfd32a792163cb5ae182fbe103698db0743a1289e8bb7205852add214d3520a695b1e40ca34fcfb47c7abbe4fb60edb39cc6de7f2396550738c6a8243be05ed0126af70c5dff6593cbc985769ce563665a8557ef01fbd564fc19f32bd424cbe624681aee11a27f66ce72408eeacc96454697ed0ce2117061b8` |
| `W_cloud` | `8113fea74d8f3f8ae31139a5fd8f6615a5b18be1802a46785ce2855bd39e94f66735b23e42c640a4707db7a4d4e23a8b8bf5084764e1492ac8c10aefd82a7732` |
| `sig_responder` | `2e1b8baf6ba142ccf88ddf577463e93896372ce90b2085dd07d4a85f48bf2a327311865d0453be0af2901ff82580306b36bcda790e844210070e3f6de0d0dbc6` |

---

## 2. 测试向量

### [KAT-1] `sm3_hex_of_ascii`

```
输入  ascii = "abc"
期望  66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0
```
该值同时是 GM/T 0004 标准给出的 `SM3("abc")` 向量，可与任意第三方 SM3 实现独立核对。

### [KAT-2] `hmac_sm3_hex` / `hmac_sm3_verify`

```
输入  key_hex  = psk        (16 字节)
      data_hex = nonce      (16 字节)
期望  d0d51b9c7f0c8939775ecf3f5a5a49fdc349dfda5d34a168e6084a84af2f7b12

hmac_sm3_verify(psk, nonce, 上述期望值)   → true
hmac_sm3_verify(psk, nonce, 64 个 '0')    → false
```

### [KAT-3] `make_id_from_bcd` / `make_id_from_ascii`

```
make_id_from_bcd("00000000000001")        → 0000000000000100000000000000000000000000000000000000000000000000
make_id_from_bcd("1")                     → 同上（不足 14 位左侧补 '0'）
make_id_from_ascii("cloud.example.com")   → 636c6f75642e6578616d706c652e636f6d000000000000000000000000000000
```
错误用例（均应抛 `clpkc::Error`）：
```
make_id_from_bcd("123456789012345")   // 15 位，超上限
make_id_from_bcd("12a4")              // 含非十进制字符
make_id_from_ascii(33 个字符)          // 超过 32 字节
```

### [KAT-4] `point_to_wire` / `point_from_wire`

```
point_from_wire(R_B)         → "04" + R_B     (65 字节 SEC1)
point_to_wire("04" + R_B)    → R_B            (64 字节裸点)
point_to_wire(R_B)           → R_B            (已是裸点，幂等)
```

### [KAT-5] `sm2_decrypt`

```
输入  d_hex      = ua_pile
      cipher_hex = cipher_pile
期望  t = 87ce2bc0c1aeb3a14ed247943c46159d24eb4f09fa779e1363a7fb6e3024a9e2
```

### [KAT-6] `compose_full_private`

```
输入  secret_hex            = ua_pile
      encrypted_partial_hex = cipher_pile      // 内部解密后合成
期望  SK_pile = 98f05f0517152b29e7d258b66f8a6b039c73e80a0b99d157b90e72f6c924bb04          // (d + t) mod n
```

### [KAT-7] `reconstruct_full_public`

```
输入  id_hex = ID_B, w_hex = W_pile,  ppub_hex = Ppub
期望  PK_pile  = ff7c8b38fc23a5412401d4e6f1778cd6e77c3968d0cb3affa25c5e3a4fa539f4b40e16da369641f9a7a6aa91b2046c3506e9f6b02f756bc76f473c462819338e

输入  id_hex = ID_A, w_hex = W_cloud, ppub_hex = Ppub
期望  PK_cloud = 76fe9e59a0d9b95b46f4704086dace3ba4e8a69cdac02f42ab07ddb9b7c518059fc5dc54b6bd21c9600180d0719e02607e8eaa10499ffffe601b4551c989badd
```
本项同时验证 `HA`（含 ENTL=`0x0100`）与 `λ` 的计算。

### [KAT-8] `verify_keypair_consistency`

```
verify_keypair_consistency(SK_pile, W_pile, Ppub, ID_B)   → true
verify_keypair_consistency(SK_pile, W_pile, Ppub, ID_A)   → false   // ID 不匹配
```

### [KAT-9] `derive_session_key` / `session_key_to_sm4`

两端各自计算应得到同一结果：
```
桩端  derive_session_key(eph_b, R_A, R_A, R_B, ID_A, ID_B, nonce)
云端  derive_session_key(eph_a, R_B, R_A, R_B, ID_A, ID_B, nonce)
期望  SK = badd7fb23a583988bda086803c8da5a9b833040df7d77bfb3f68fbffa74e0d00

session_key_to_sm4(SK)   → badd7fb23a583988bda086803c8da5a9     // SK 前 16 字节
```

### [KAT-10] `verify_responder`

`sig_responder` 是对响应方 transcript 的合法签名，用云端完整公钥 `PK_cloud` 验签：
```
verify_responder(R_A, R_B, ID_A, W_cloud, nonce, sig_responder, PK_cloud)  → true
```
篡改用例（均应返回 `false`，且不抛异常）：
```
nonce 末字节改为 ff                          → false
sig_raw_hex 全 0                             → false
pk_hex 用 PK_pile（错误的公钥）               → false
```

### [KAT-11] `sign_initiator` + `verify_initiator`

SM2 签名含随机数 `k`，相同输入每次输出不同，因此本项不给固定签名值，改为验证往返：
```
sig = sign_initiator(R_B, ID_B, W_pile, nonce, SK_pile)
  → 长度必为 128 hex
verify_initiator(R_B, ID_B, W_pile, nonce, sig, PK_pile)              → true
verify_initiator(R_B, ID_B, W_pile, nonce 末字节改 ff, sig, PK_pile)  → false
```

### [KAT-12] `generate_static_key` / `random_bytes_hex`

```
generate_static_key()      → secret_hex 64 hex、public_hex 128 hex，两次调用结果不同
random_bytes_hex(16)    → 32 hex，两次调用结果不同
```

### [KAT-13] 错误处理

```
reconstruct_full_public("00", W_pile, Ppub)   → 抛 clpkc::Error（ID 长度非法）
session_key_to_sm4("abcd")                    → 抛 clpkc::Error（长度非法）
```

---

## 3. 覆盖对照

| README §  | 算法环节 | 对应向量 |
|---|---|---|
| 4.2 | ID 构造（BCD / ASCII） | KAT-3 |
| 4.3 | `HA` / `λ` / 公钥重建 / 私钥合成 | KAT-6、KAT-7、KAT-8 |
| 4.4 | SM2 解密（C1C3C2） | KAT-5 |
| 4.5 | 两段 transcript 与 SM2 签名 | KAT-10、KAT-11 |
| 4.6 | 会话密钥与 SM4 密钥 | KAT-9 |
| 4.7 | HMAC-SM3 | KAT-2 |
| §3 | 点编码约定 | KAT-4 |
| §6 | 错误处理约定 | KAT-3、KAT-10、KAT-13 |
