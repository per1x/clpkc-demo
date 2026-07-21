# CL-PKC 桩端 SDK —— KAT 测试向量

本文件给出**固定输入 → 期望输出**的已知答案测试向量，供集成方接入后自验。

> **所有期望值均已与 Java 云端（`cloud-service` 的 `ClpkcCrypto`，BouncyCastle 实现）交叉验证一致。**
> 不是 C++ 自己验自己 —— 见文末「交叉验证结论」与「如何复现」。

运行自检：
```bash
cmake -S . -B build && cmake --build build
cd build && make test      # 或直接 ./clpkc_selftest
```
当前状态：**32 项全部通过**。

---

## 0. 通用约定

- 所有值均为 **hex 字符串**（输出小写）。
- 点 = 64 字节裸 `X‖Y`（无 04）；标量 = 32 字节；签名 = 64 字节裸 `r‖s`。
- **ID = 32 字节零补齐**，`HA / ZA / transcript / KDF` 四处统一，ENTL 恒为 `0x0100`。
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
| `id_pile` (ASCII) | `pile-001` |
| `id_cloud` (ASCII) | `cloud-001` |

由上述标量确定性导出（Java/C++ 一致，跨运行稳定）：

| 名称 | 值 |
|---|---|
| `Ppub` | `344081b80805540a38d71d721bd072d8957eae15aeb852e72086ab4c5962b89b5bb8628b9d9c4edd30f341a5a25886c063cff46dc04c7e68f2efb3b58830e0f3` |
| `R_B` | `d7bddda6449033e3202e9d1633d28584b23624c77f0091c745e5c8c7fc13df8a91e03e64c5646c62deb6f12dd80a699c2c61b95c80a768a991d7e6df292e0a63` |
| `R_A` | `d362a0cb4932a4beba9f1fd22879ffe0e2ffaf65987aaa19b1a4e7d5877be3db844fbdf0065ffcaa35111ccdb9b1321941d907b23f3cf19852fec8b5b4881d22` |

**冻结值**（KGC 颁发含随机 w、SM2 签名含随机 k，故固定下来作为 KAT 输入）：

| 名称 | 值 |
|---|---|
| `W_pile` | `e19562f61b4a2befece57ae868322b80b97ee8bcf32e600524446636ffc5b1419edf41dc326d04460fff721d3a77103ff0446a412069d3e473ab57a0ed7e9d88` |
| `cipher_pile`（129B C1C3C2） | `04612b15de497c992f4665dbb7b0e4555913cedbe3e8e26914b917c24573d65653f1162a4b9e508e261f863cf40f38087d9a5f9801637028d3aab01c1d919eaaa2fba908442cf18bd76104fa4d0e23fe57fb7e4beb55f70a57c7cf7853ee036df20dc39390de77301f1dae228c01afe25dbbc11fdbfc6bcb777705c1c5eff9c597` |
| `W_cloud` | `513766cab63b2c6a4bd2ba643ecda4b54da3b941f46434af3a7427bd8fa2d75bc7c064dcf63a149f82f281c65cac8cc25810ff5a7359ea4a068c4fa85a29d983` |
| `sig_responder`（Java 产出） | `85d9004a1a7a86798cb6f43471f5bde88f70e228ba4740bd8e8d5f364c1f96a425e2356913cfed174d534636574cdbfafd3012600b885e75c5e13ddc9e6ca966` |

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

### KAT-3 ID 编码（32 字节零补齐）
```
make_id_from_ascii("pile-001")
→ 70696c652d303031000000000000000000000000000000000000000000000000
make_id_from_ascii("cloud-001")
→ 636c6f75642d3030310000000000000000000000000000000000000000000000
make_id_from_bcd("00000000000001")            // 7 字节 BCD 放前 7 字节
→ 0000000000000100000000000000000000000000000000000000000000000000
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
→ t_pile = c3d327ec98da76f2bd7dc2cef6d0bd016ab7ffe0d4e92edbe8d8408d2095f3dd
```

### KAT-6 合成完整私钥
```
compose_full_private(d_hex=ua_pile, t_hex=t_pile)     // (d+t) mod n
→ SK_pile = d4f55b30ee40ee7b567dd3f12a151267e24098e0e60b62203e3eb815b99604ff
```

### KAT-7 完整公钥重建（λ / HA，ENTL=0x0100）
```
reconstruct_full_public(id_hex=ID32(pile-001), w_hex=W_pile, ppub_hex=Ppub)
→ PK_pile = e05de511ca340f30dfa686f98a4b4fbf0f8c080b22ce7527e8640805db3dbb40d7d421d170566b7e0f550458ce8046092f6be3164c32bfc2080ab392b0182d23

reconstruct_full_public(id_hex=ID32(cloud-001), w_hex=W_cloud, ppub_hex=Ppub)
→ PK_cloud = b1611e3a53ed78714ed8693b70f90bf7c6435e15250d8f2c130bfa3cf5cb46b424ba107e364c097dc26628297bb02705bd86cdaab5b487695816dbb7363dfbed
```

### KAT-8 密钥对自洽
```
verify_keypair_consistency(SK_pile, W_pile, Ppub, ID32(pile-001)) → true
verify_keypair_consistency(SK_pile, W_pile, Ppub, ID32(cloud-001)) → false   // 错 ID
```

### KAT-9 会话密钥
```
桩侧: derive_session_key(eph_secret=eph_b, peer_point=R_A, R_A, R_B, ID32(cloud-001), ID32(pile-001), nonce)
云侧: derive_session_key(eph_secret=eph_a, peer_point=R_B, R_A, R_B, ID32(cloud-001), ID32(pile-001), nonce)
两者相等 → 5327df76e796b34f9ba804d987c0748628859631ab8e0a53cb5d9618a8eaea80

session_key_to_sm4(上值)     // 取前 16 字节
→ 5327df76e796b34f9ba804d987c07486
```

### KAT-10 验云端(响应方)签名 —— **Java 签、C++ 验**
```
verify_responder(R_A, R_B, ID32(cloud-001), W_cloud, nonce, sig_responder, PK_cloud) → true
篡改 nonce（末字节改 ff）  → false
签名全 0                   → false
用 PK_pile 当公钥          → false
```

### KAT-11 发起方签名往返
> SM2 签名含随机 k，**同样输入每次输出不同属正常**，故不给固定签名值，只验往返。
```
sig = sign_initiator(R_B, ID32(pile-001), W_pile, nonce, SK_pile)
verify_initiator(R_B, ID32(pile-001), W_pile, nonce, sig, PK_pile) → true
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
