# CL-PKC 桩端 SDK —— KAT 测试向量

本文件给出**固定输入 → 期望输出**的已知答案测试向量，供集成方接入后自验。

> **所有期望值均已与 Java 云端（`cloud-service` 的 `ClpkcCrypto`，BouncyCastle 实现）交叉验证一致。**
> 不是 C++ 自己验自己 —— 见文末「交叉验证结论」与「如何复现」。

运行自检：
```bash
cmake -S . -B build && cmake --build build
cd build && make test      # 或直接 ./clpkc_selftest
```
当前状态：**35 项全部通过**。

> ⚠️ **破坏性变更**：本版 ID 规则已改（桩=7B BCD 主机编号 / 云=域名 ASCII，线上传 64 hex），
> 且 nonce 进 transcript/KDF 改为 16 原始字节。**旧向量、旧 keystore 全部失效，需重新开通。**

---

## 0. 通用约定

- 所有值均为 **hex 字符串**（输出小写）。
- 点 = 64 字节裸 `X‖Y`（无 04）；标量 = 32 字节；签名 = 64 字节裸 `r‖s`。
- **ID = 32 字节**（`HA / ZA / transcript / KDF` 四处统一，ENTL 恒为 `0x0100`），线上/接口一律传 **64 字符 hex**：
  - **桩 ID_B** = 7 字节 BCD 主机编号 ‖ 25 字节 `0x00`（主机编号 ≤14 位十进制，不足**左侧补 `'0'`**）
  - **云 ID_A** = 域名 ASCII 字节 ‖ `0x00` 补齐到 32 字节
- **统一规则：所有进哈希/签名的字段一律「解码后的原始字节」，绝不用 hex 文本。**
  nonce 在 transcript / KDF / HMAC **三处都是解码后的 16 原始字节**（早期版本 transcript/KDF
  曾用 hex 文本的 ASCII，已于本次统一修正，属破坏性变更）。

---

## 1. 固定输入

| 名称 | 值 |
|---|---|
| `ms`（KGC 主私钥，仅用于生成本向量） | `0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef` |
| `ua_pile`（桩本机私钥 u_B） | `1122334455667788990011223344556677889900112233445566778899001122` |
| `ua_cloud`（云本机私钥） | `2233445566778899001122334455667788990011223344556677889900112233` |
| `eph_b`（桩临时私钥 b） | `3344556677889900112233445566778899001122334455667788990011223344` |
| `eph_a`（云临时私钥 a） | `4455667788990011223344556677889900112233445566778899001122334455` |
| `nonce` | `0102030405060708090a0b0c0d0e0f10` |
| `psk`（预共享密钥） | `00112233445566778899aabbccddeeff` |
| `host_no`（桩主机编号，十进制） | `00000000000001` |
| `ID_B`（= 7B BCD ‖ 25B 0x00） | `0000000000000100000000000000000000000000000000000000000000000000` |
| `domain`（云域名） | `cloud.example.com` |
| `ID_A`（= ASCII ‖ 0x00 补齐） | `636c6f75642e6578616d706c652e636f6d000000000000000000000000000000` |

由上述标量确定性导出（Java/C++ 一致，跨运行稳定）：

| 名称 | 值 |
|---|---|
| `Ppub` | `344081b80805540a38d71d721bd072d8957eae15aeb852e72086ab4c5962b89b5bb8628b9d9c4edd30f341a5a25886c063cff46dc04c7e68f2efb3b58830e0f3` |
| `R_B` | `d7bddda6449033e3202e9d1633d28584b23624c77f0091c745e5c8c7fc13df8a91e03e64c5646c62deb6f12dd80a699c2c61b95c80a768a991d7e6df292e0a63` |
| `R_A` | `d362a0cb4932a4beba9f1fd22879ffe0e2ffaf65987aaa19b1a4e7d5877be3db844fbdf0065ffcaa35111ccdb9b1321941d907b23f3cf19852fec8b5b4881d22` |

**冻结值**（KGC 颁发含随机 w、SM2 签名含随机 k，故固定下来作为 KAT 输入）：

| 名称 | 值 |
|---|---|
| `W_pile` | `c40387e9a0d933cfe840e343ec6df4d227c9901654cdac8186cd1825e4958da5030a5b74e617f483ef688d8b01e6dbd8ae2f6ed102decea8e8b4367f714e6ca9` |
| `cipher_pile`（129B C1C3C2） | `04403ca4451e324adfd32a792163cb5ae182fbe103698db0743a1289e8bb7205852add214d3520a695b1e40ca34fcfb47c7abbe4fb60edb39cc6de7f2396550738c6a8243be05ed0126af70c5dff6593cbc985769ce563665a8557ef01fbd564fc19f32bd424cbe624681aee11a27f66ce72408eeacc96454697ed0ce2117061b8` |
| `W_cloud` | `8113fea74d8f3f8ae31139a5fd8f6615a5b18be1802a46785ce2855bd39e94f66735b23e42c640a4707db7a4d4e23a8b8bf5084764e1492ac8c10aefd82a7732` |
| `sig_responder`（Java 产出） | `2e1b8baf6ba142ccf88ddf577463e93896372ce90b2085dd07d4a85f48bf2a327311865d0453be0af2901ff82580306b36bcda790e844210070e3f6de0d0dbc6` |

---

## 2. 测试向量

### KAT-1 SM3
```
sm3_hex("616263")   // "abc"
→ 66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0
```
✅ 同时符合 **GM/T 0004 标准 SM3("abc") 向量**（第三方可独立核对）。

### KAT-2 HMAC-SM3
```
hmac_sm3_hex(key_hex=psk, data_hex=nonce)      // 注意：两者都先 hex 解码
→ d0d51b9c7f0c8939775ecf3f5a5a49fdc349dfda5d34a168e6084a84af2f7b12
hmac_sm3_verify(psk, nonce, 上值) → true
hmac_sm3_verify(psk, nonce, 全 0)  → false
```

### KAT-3 ID 构造（新规则）
```
// 桩 ID_B：7 字节 BCD 主机编号 ‖ 25 字节 0x00
make_id_from_bcd("00000000000001")   → 0000000000000100000000000000000000000000000000000000000000000000
make_id_from_bcd("1")                → 同上（不足 14 位左侧补 '0'，数值不变）

// 云 ID_A：域名 ASCII ‖ 0x00 补齐到 32 字节
make_id_from_ascii("cloud.example.com") → 636c6f75642e6578616d706c652e636f6d000000000000000000000000000000

// 边界：均应报错
make_id_from_bcd("123456789012345")  // 15 位 → Error
make_id_from_bcd("12a4")             // 非十进制 → Error
make_id_from_ascii(33 个字符)         // 超 32 字节 → Error
```
字节级拆解：
```
ID_B: 00 00 00 00 00 00 01 | 00 × 25      (7B BCD "00000000000001" + 25B 零)
ID_A: 63 6c 6f 75 64 2e 65 78 61 6d 70 6c 65 2e 63 6f 6d | 00 × 15
      c  l  o  u  d  .  e  x  a  m  p  l  e  .  c  o  m    (17B ASCII + 15B 零)
```

### KAT-4 点编码
```
point_from_wire(R_B)        → "04" + R_B      (65 字节 SEC1)
point_to_wire("04"+R_B)     → R_B             (64 字节裸点)
point_to_wire(R_B)          → R_B             (已是裸点，幂等)
```

### KAT-5 SM2 解密（部分私钥）
```
sm2_decrypt(d_hex=ua_pile, cipher_hex=cipher_pile)
→ t_pile = 87ce2bc0c1aeb3a14ed247943c46159d24eb4f09fa779e1363a7fb6e3024a9e2
```

### KAT-6 合成完整私钥
```
compose_full_private(d_hex=ua_pile, t_hex=t_pile)     // (d+t) mod n
→ SK_pile = 98f05f0517152b29e7d258b66f8a6b039c73e80a0b99d157b90e72f6c924bb04
```

### KAT-7 完整公钥重建（λ / HA，ENTL=0x0100）
```
reconstruct_full_public(id_hex=ID_B, w_hex=W_pile, ppub_hex=Ppub)
→ PK_pile = ff7c8b38fc23a5412401d4e6f1778cd6e77c3968d0cb3affa25c5e3a4fa539f4b40e16da369641f9a7a6aa91b2046c3506e9f6b02f756bc76f473c462819338e

reconstruct_full_public(id_hex=ID_A, w_hex=W_cloud, ppub_hex=Ppub)
→ PK_cloud = 76fe9e59a0d9b95b46f4704086dace3ba4e8a69cdac02f42ab07ddb9b7c518059fc5dc54b6bd21c9600180d0719e02607e8eaa10499ffffe601b4551c989badd
```

### KAT-8 密钥对自洽
```
verify_keypair_consistency(SK_pile, W_pile, Ppub, ID_B) → true
verify_keypair_consistency(SK_pile, W_pile, Ppub, ID_A) → false   // 错 ID
```

### KAT-9 会话密钥
```
桩侧: derive_session_key(eph_secret=eph_b, peer_point=R_A, R_A, R_B, ID_A, ID_B, nonce)
云侧: derive_session_key(eph_secret=eph_a, peer_point=R_B, R_A, R_B, ID_A, ID_B, nonce)
两者相等 → badd7fb23a583988bda086803c8da5a9b833040df7d77bfb3f68fbffa74e0d00

session_key_to_sm4(上值)     // 取前 16 字节
→ badd7fb23a583988bda086803c8da5a9
```

### KAT-10 验云端(响应方)签名 —— **Java 签、C++ 验**
```
verify_responder(R_A, R_B, ID_A, W_cloud, nonce, sig_responder, PK_cloud) → true
篡改 nonce（末字节改 ff）  → false
签名全 0                   → false
用 PK_pile 当公钥          → false
```

### KAT-11 发起方签名往返
> SM2 签名含随机 k，**同样输入每次输出不同属正常**，故不给固定签名值，只验往返。
```
sig = sign_initiator(R_B, ID_B, W_pile, nonce, SK_pile)
verify_initiator(R_B, ID_B, W_pile, nonce, sig, PK_pile) → true
篡改 nonce → false
```

### KAT-12 / KAT-13 生成与错误处理
```
generate_keypair()          → secret 64 hex / public 128 hex，两次调用不同
random_bytes_hex(16)        → 32 hex，两次调用不同
reconstruct_full_public("00", ...)   → 抛 clpkc::Error（ID 长度非法）
session_key_to_sm4("abcd")           → 抛 clpkc::Error（长度非法）
```

---

## 3. 交叉验证结论

| 方向 | 内容 | 结果 |
|---|---|---|
| **Java → C++** | KAT-2/5/6/7/9 的全部期望值由 Java `ClpkcCrypto` 算出，C++ SDK 逐项复现 | ✅ 一致 |
| **Java 签 → C++ 验** | Java `signResponder` 产出 `sig_responder`，C++ `verify_responder` 校验（KAT-10） | ✅ true |
| **C++ 签 → Java 验** | C++ `sign_initiator` 产出签名，Java `verifyInitiator` 校验 | ✅ `java_verifies_cpp_initiator_sig=true` |
| **双方会话密钥** | 桩侧/云侧分别派生 | ✅ 相等，且与 Java `deriveSessionKey` 一致 |
| **外部标准** | `SM3("abc")` 对照 GM/T 0004 标准向量 | ✅ 一致 |

> 这说明 **ID 32 字节补齐、ENTL=0x0100、transcript 拼接顺序、nonce 的 16 原始字节用法、
> 点与签名的线上编码** 在 C++ SDK 与 Java 云端之间**逐字节一致**。

## 4. 如何复现交叉验证

```bash
# 1) C++ 侧：跑 KAT，并拿到一枚 C++ 产出的 initiator 签名（输出最后一行）
cd pile-sdk && cmake -S . -B build && cmake --build build
SIG=$(./build/clpkc_selftest | tail -1)

# 2) Java 侧：用 cloud-service 的实现算同一组输入，并验 C++ 的签名
cd ..
mvn -q -f cloud-service/pom.xml package -DskipTests
mvn -q -f cloud-service/pom.xml dependency:build-classpath -Dmdep.outputFile=/tmp/cp.txt
CP="cloud-service/target/classes:$(cat /tmp/cp.txt)"
javac -cp "$CP" -d /tmp/katbuild pile-sdk/tools/KatGen.java
java  -cp "/tmp/katbuild:$CP" KatGen "$SIG"
```
把 `KatGen` 输出的 `name=value` 与本文件第 2 节逐行比对即可。

> ⚠️ `W_pile / cipher_pile / W_cloud / sig_responder` 每次运行都会变（含随机 w/k），
> 属正常；它们是本 KAT 的**冻结输入**，不要拿新一次运行的值去比对。
> 确定性字段（`Ppub / R_A / R_B / hmac / sm3_abc / session_key / sm4_key`）跨运行必须稳定。
