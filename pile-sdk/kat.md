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
- **nonce 有两种用法，切勿混淆**：
  - 参与 transcript / KDF 时，绑定的是 nonce **hex 串的 ASCII 字节**（32 字节）；
  - 计算 HMAC 时，用的是 **hex 解码后的 16 原始字节**。

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
| `W_pile` | `8b77aba1b8eb7a0df8131058f70a530b380e45e97237f10f7d0a6ea1be18e158569211790e4e77e087fdf412cca00c4ffddbffdcb987beac2236b72500fccf7c` |
| `cipher_pile`（129B C1C3C2） | `0492a18dbd7d05fef39fad26ea10627365c2c9e1893ce43f9c06c9c3e2c608978dddd75a867411622f02466dce443e4e1f48f63e924eab69d52e7eec0d899998540515079cd166c36aa4b0fe51e755bea5ac52e63ed1aa74e64e2c64f1ba5bc3e815bb52d00fbea578e2b1d1a91e2b73b5c219c3b028c2c273cdd43d5d347a4e13` |
| `W_cloud` | `133a84aff21a13453755a96bd9a245e701be1543d314dbdb1afeefb7a0f9ec73df135d98a634586cb345e796ee18735254c3a57ec92edd8d31e847c9df50c3e7` |
| `sig_responder`（Java 产出） | `80a095e58290af0544a4a1c31c0bfe4a9a2e766c8a683ec1dc3de44461eb07f2d309b77bbb8a56ff81e817754c74ae9fa93ea6780559339815fe5bb902621790` |

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
→ t_pile = cbd2186bd0ec4539685dd0391c1c9b99edbad4c891ce9998bf69e311a2535402
```

### KAT-6 合成完整私钥
```
compose_full_private(d_hex=ua_pile, t_hex=t_pile)     // (d+t) mod n
→ SK_pile = dcf44bb02652bcc2015de15b4f60f10065436dc8a2f0ccdd14d05a9a3b536524
```

### KAT-7 完整公钥重建（λ / HA，ENTL=0x0100）
```
reconstruct_full_public(id_hex=ID32(pile-001), w_hex=W_pile, ppub_hex=Ppub)
→ PK_pile = 1761f4ec4d1d2edb7d04fc7a187e58b9351db8ee0e79cf6e6494596443da5df9897dc95ef97269cd9061ed27d8f6a8088d9eb24b65fcea6d4f42eee98d8c9ae3

reconstruct_full_public(id_hex=ID32(cloud-001), w_hex=W_cloud, ppub_hex=Ppub)
→ PK_cloud = adacb29b486f2cc7b4a0eb0ac1ca6fc23d2b01e83fe7a748f3a6a319f46b11162ef67795821ddb5c7ee7618d808a9fce96987f6da1a76d49fb575c659d997256
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
两者相等 → 4523389b56cc99e56146b7d4fce60ebeeddf9e484b831cd9151f43d4edff5d97

session_key_to_sm4(上值)     // 取前 16 字节
→ 4523389b56cc99e56146b7d4fce60ebe
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

> 这说明 **ID 32 字节补齐、ENTL=0x0100、transcript 拼接顺序、nonce 的 ASCII/原始字节双重用法、
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
