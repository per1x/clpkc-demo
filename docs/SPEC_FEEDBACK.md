# 技术联络单 附录 A.3 反馈清单

本文件是**给对方的联络单修订建议**，记录附录 A.3（桩端 C++ 函数）与 `pile-sdk/` 实际交付
接口的差异。**不属于 SDK 交付文档**——SDK 的 [`README.md`](../pile-sdk/README.md) 与
[`kat.md`](../pile-sdk/kat.md) 只描述当前实现，不含任何待议内容。

对照基准：`pile-sdk/clpkc_sdk.h`。

---

## 一、待修订项

### 1. A.3.7 `verify_responder` 的签名参数名 —— **已拍板：改为 `sig_raw_hex`**

| 项 | 内容 |
|---|---|
| 联络单现写法 | `verify_responder(..., **sig_der_hex**, ...)` |
| 实际情况 | 该参数承载的是 **裸 `r‖s`，共 64 字节（128 hex）**，**不是 DER 编码** |
| **结论** | **附录 A.3.7 的 `sig_der_hex` 应改为 `sig_raw_hex`**，两边统一用 raw |
| 实现现状 | SDK 与云端 Java 侧均已使用 raw 形式；`clpkc_sdk.h` 的参数名即为 `sig_raw_hex`，无需改动 |

> 保留 `sig_der_hex` 会误导实现方按 DER 去解析这 64 字节，导致验签必然失败，故必须修订联络单。

---

## 二、A.3 九个函数的对齐状态

`pile-sdk` 已按 A.3 完成命名对齐，当前状态如下：

| A.3 | SDK 实际签名 | 状态 |
|---|---|---|
| A.3.1 `generate_static_key` | `KeyMaterial generate_static_key()` | ✅ 一致（返回结构体 `KeyMaterial{secret_hex, public_hex}`） |
| A.3.2 `random_bytes_hex` | `std::string random_bytes_hex(int n_bytes)` | ✅ 一致 |
| A.3.3 `hmac_sm3_hex` | `std::string hmac_sm3_hex(key_hex, data_hex)` | ✅ 一致 |
| A.3.4 `compose_full_private` | `std::string compose_full_private(secret_hex, encrypted_partial_hex)` | ✅ 一致（第 2 参为密文，内部解密后合成） |
| A.3.5 `reconstruct_full_public` | `std::string reconstruct_full_public(id_hex, claimed_public_hex, master_public_hex)` | ✅ 一致（见下方待明确项 1） |
| A.3.6 `sign_initiator` | `std::string sign_initiator(r_pile_hex, id, w_hex, nonce, full_private_hex)` | ✅ 一致 |
| A.3.7 `verify_responder` | `bool verify_responder(r_a_hex, r_b_hex, id, w_hex, nonce, sig_raw_hex, full_public_hex)` | ⚠️ 除 `sig_der_hex`→`sig_raw_hex`（见第一节）外一致 |
| A.3.8 `derive_session_key` | `std::string derive_session_key(eph_secret_hex, peer_point_hex, ra_hex, rb_hex, ida_hex, idb_hex, nonce)` | ✅ 一致 |
| A.3.9 `sm3_hex_of_ascii` | `std::string sm3_hex_of_ascii(const std::string& ascii)` | ✅ 一致（对入参字符串的原始字节做 SM3） |

---

## 三、建议补进附录 A.3 的函数

以下函数 SDK 已提供、A.3 尚未收录。建议补入，以便双方接口清单一致：

| # | 签名 | 用途 |
|---|---|---|
| 1 | `std::string sm2_decrypt(d_hex, cipher_hex)` | 单独解密部分私钥密文。`compose_full_private` 内部已包含此步；单独暴露便于开通失败时区分"解密失败"还是"合成失败" |
| 2 | `bool hmac_sm3_verify(key_hex, data_hex, expected_mac_hex)` | **常量时间**校验 HMAC，防时序侧信道。校验对端 MAC 应强制使用，不应自行用 `==` 比较 |
| 3 | `bool verify_keypair_consistency(full_private_hex, claimed_public_hex, master_public_hex, id_hex)` | 校验 `SK·G == W + λ·Ppub`。开通流程落盘前自检，避免持久化不自洽的密钥材料 |
| 4 | `bool verify_initiator(r_pile_hex, id, w_hex, nonce, sig_raw_hex, full_public_hex)` | 与 `sign_initiator` 配对的验签，供离线自检与联调定位 |
| 5 | `std::string session_key_to_sm4(sk32_hex)` | 取会话密钥前 16 字节作 SM4 密钥 |
| 6 | `std::string make_id_from_bcd(host_no_decimal)` | 构造桩 `ID_B` = 7 字节 BCD 主机编号 ‖ 25 字节 `0x00`（主机编号 ≤14 位十进制，不足左侧补 `'0'`） |
| 7 | `std::string make_id_from_ascii(ascii)` | 构造云 `ID_A` = 域名 ASCII ‖ `0x00` 补齐到 32 字节 |
| 8 | `std::string point_to_wire(point_hex)` | 65 字节 SEC1(`04‖X‖Y`) 或 64 字节裸点 → 统一 64 字节裸点（线上格式） |
| 9 | `std::string point_from_wire(wire_hex)` | 64 字节裸点 → 65 字节 SEC1，供需要 SEC1 输入的库使用 |

---

## 四、待对方明确的项

### 1. ID 参数的命名统一

A.3 中 ID 参数在不同函数里写法不一：`sign_initiator` 写作 `id`，而 `reconstruct_full_public`
一侧目前实现为 `id_hex`。两者承载的都是**同一个 32 字节 ID 的 64 字符 hex**，仅命名不同。

| 函数 | 当前 ID 参数名 |
|---|---|
| `sign_initiator` / `verify_responder` / `verify_initiator` | `id` |
| `reconstruct_full_public` / `verify_keypair_consistency` | `id_hex` |

建议二者统一（推荐统一为 `id_hex`，与其它 hex 入参的命名风格一致），请对方确认后一并修订
联络单与 SDK。此项**不影响任何功能与线上格式**，纯命名。
