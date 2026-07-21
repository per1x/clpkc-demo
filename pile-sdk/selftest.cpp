// ============================================================================
// CL-PKC 桩端 SDK —— KAT(已知答案测试) 自检。
//
// 所有期望值均由 **Java 云端(cloud-service) ClpkcCrypto 交叉验证** 产出，
// 见 kat.md。运行：`make test` 或直接执行 clpkc_selftest。
// 全部通过时退出码 0，任一失败退出码 1。
// ============================================================================

#include <cstdio>
#include <string>

#include "clpkc_sdk.h"

namespace {

int g_pass = 0;
int g_fail = 0;

void check(const std::string& name, const std::string& actual, const std::string& expect) {
    if (actual == expect) {
        g_pass++;
        std::printf("  [PASS] %s\n", name.c_str());
    } else {
        g_fail++;
        std::printf("  [FAIL] %s\n         expect: %s\n         actual: %s\n",
                    name.c_str(), expect.c_str(), actual.c_str());
    }
}

void check_bool(const std::string& name, bool actual, bool expect) {
    if (actual == expect) {
        g_pass++;
        std::printf("  [PASS] %s\n", name.c_str());
    } else {
        g_fail++;
        std::printf("  [FAIL] %s  expect=%s actual=%s\n", name.c_str(),
                    expect ? "true" : "false", actual ? "true" : "false");
    }
}

// ---------------- KAT 固定输入 ----------------
const std::string MS_HEX    = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const std::string UA_PILE   = "1122334455667788990011223344556677889900112233445566778899001122";
const std::string UA_CLOUD  = "2233445566778899001122334455667788990011223344556677889900112233";
const std::string EPH_B     = "3344556677889900112233445566778899001122334455667788990011223344";
const std::string EPH_A     = "4455667788990011223344556677889900112233445566778899001122334455";
const std::string NONCE     = "0102030405060708090a0b0c0d0e0f10";
const std::string PSK       = "00112233445566778899aabbccddeeff";

// 由 KGC(Java) 颁发、冻结进 KAT 的值（含随机 w/k，故固定下来）
const std::string PPUB =
    "344081b80805540a38d71d721bd072d8957eae15aeb852e72086ab4c5962b89b"
    "5bb8628b9d9c4edd30f341a5a25886c063cff46dc04c7e68f2efb3b58830e0f3";
const std::string RB =
    "d7bddda6449033e3202e9d1633d28584b23624c77f0091c745e5c8c7fc13df8a"
    "91e03e64c5646c62deb6f12dd80a699c2c61b95c80a768a991d7e6df292e0a63";
const std::string RA =
    "d362a0cb4932a4beba9f1fd22879ffe0e2ffaf65987aaa19b1a4e7d5877be3db"
    "844fbdf0065ffcaa35111ccdb9b1321941d907b23f3cf19852fec8b5b4881d22";
const std::string W_PILE =
    "8b77aba1b8eb7a0df8131058f70a530b380e45e97237f10f7d0a6ea1be18e158"
    "569211790e4e77e087fdf412cca00c4ffddbffdcb987beac2236b72500fccf7c";
const std::string CIPHER_PILE =
    "0492a18dbd7d05fef39fad26ea10627365c2c9e1893ce43f9c06c9c3e2c60897"
    "8dddd75a867411622f02466dce443e4e1f48f63e924eab69d52e7eec0d899998"
    "540515079cd166c36aa4b0fe51e755bea5ac52e63ed1aa74e64e2c64f1ba5bc3"
    "e815bb52d00fbea578e2b1d1a91e2b73b5c219c3b028c2c273cdd43d5d347a4e13";
const std::string W_CLOUD =
    "133a84aff21a13453755a96bd9a245e701be1543d314dbdb1afeefb7a0f9ec73"
    "df135d98a634586cb345e796ee18735254c3a57ec92edd8d31e847c9df50c3e7";
const std::string SIG_RESPONDER =
    "80a095e58290af0544a4a1c31c0bfe4a9a2e766c8a683ec1dc3de44461eb07f2"
    "d309b77bbb8a56ff81e817754c74ae9fa93ea6780559339815fe5bb902621790";

// ---------------- KAT 期望输出（Java 交叉验证一致）----------------
const std::string ID_PILE_HEX =
    "70696c652d303031000000000000000000000000000000000000000000000000";
const std::string ID_CLOUD_HEX =
    "636c6f75642d3030310000000000000000000000000000000000000000000000";
const std::string ID_BCD_HEX =
    "00000000000001" "00000000000000000000000000000000000000000000000000";
const std::string T_PILE  = "cbd2186bd0ec4539685dd0391c1c9b99edbad4c891ce9998bf69e311a2535402";
const std::string SK_PILE = "dcf44bb02652bcc2015de15b4f60f10065436dc8a2f0ccdd14d05a9a3b536524";
const std::string PK_PILE =
    "1761f4ec4d1d2edb7d04fc7a187e58b9351db8ee0e79cf6e6494596443da5df9"
    "897dc95ef97269cd9061ed27d8f6a8088d9eb24b65fcea6d4f42eee98d8c9ae3";
const std::string PK_CLOUD =
    "adacb29b486f2cc7b4a0eb0ac1ca6fc23d2b01e83fe7a748f3a6a319f46b1116"
    "2ef67795821ddb5c7ee7618d808a9fce96987f6da1a76d49fb575c659d997256";
const std::string HMAC_EXP  = "d0d51b9c7f0c8939775ecf3f5a5a49fdc349dfda5d34a168e6084a84af2f7b12";
const std::string SM3_ABC   = "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0";
const std::string SESS_KEY  = "4523389b56cc99e56146b7d4fce60ebeeddf9e484b831cd9151f43d4edff5d97";
const std::string SM4_KEY   = "4523389b56cc99e56146b7d4fce60ebe";

}  // namespace

int main() {
    std::printf("=== CL-PKC 桩端 SDK KAT 自检 ===\n\n");

    // --- KAT-1 SM3（同时符合 GM/T 0004 标准向量 SM3("abc")）---
    std::printf("[KAT-1] SM3\n");
    check("sm3_hex(\"abc\")", clpkc::sm3_hex("616263"), SM3_ABC);

    // --- KAT-2 HMAC-SM3 ---
    std::printf("[KAT-2] HMAC-SM3\n");
    check("hmac_sm3_hex(PSK, nonce)", clpkc::hmac_sm3_hex(PSK, NONCE), HMAC_EXP);
    check_bool("hmac_sm3_verify 正确 MAC", clpkc::hmac_sm3_verify(PSK, NONCE, HMAC_EXP), true);
    check_bool("hmac_sm3_verify 错误 MAC",
               clpkc::hmac_sm3_verify(PSK, NONCE, std::string(64, '0')), false);

    // --- KAT-3 ID 编码 ---
    std::printf("[KAT-3] ID 编码（32 字节零补齐）\n");
    check("make_id_from_ascii(\"pile-001\")", clpkc::make_id_from_ascii("pile-001"), ID_PILE_HEX);
    check("make_id_from_ascii(\"cloud-001\")", clpkc::make_id_from_ascii("cloud-001"), ID_CLOUD_HEX);
    check("make_id_from_bcd(\"00000000000001\")",
          clpkc::make_id_from_bcd("00000000000001"), ID_BCD_HEX);

    // --- KAT-4 点编码 ---
    std::printf("[KAT-4] 点编码 wire(64B 裸) <-> SEC1(65B)\n");
    check("point_from_wire 加 04", clpkc::point_from_wire(RB), "04" + RB);
    check("point_to_wire 去 04", clpkc::point_to_wire("04" + RB), RB);
    check("point_to_wire 幂等(已是裸点)", clpkc::point_to_wire(RB), RB);

    // --- KAT-5 SM2 解密 部分私钥 ---
    std::printf("[KAT-5] sm2_decrypt（C1C3C2，129 字节密文）\n");
    check("sm2_decrypt(ua_pile, cipher)", clpkc::sm2_decrypt(UA_PILE, CIPHER_PILE), T_PILE);

    // --- KAT-6 合成完整私钥 ---
    std::printf("[KAT-6] compose_full_private\n");
    check("compose_full_private(ua, t)", clpkc::compose_full_private(UA_PILE, T_PILE), SK_PILE);

    // --- KAT-7 完整公钥重建（λ / HA，ENTL=0x0100）---
    std::printf("[KAT-7] reconstruct_full_public\n");
    check("reconstruct(id_pile, W_pile, Ppub)",
          clpkc::reconstruct_full_public(ID_PILE_HEX, W_PILE, PPUB), PK_PILE);
    check("reconstruct(id_cloud, W_cloud, Ppub)",
          clpkc::reconstruct_full_public(ID_CLOUD_HEX, W_CLOUD, PPUB), PK_CLOUD);

    // --- KAT-8 密钥对自洽 ---
    std::printf("[KAT-8] verify_keypair_consistency（SK·G == W + λ·Ppub）\n");
    check_bool("正确密钥对",
               clpkc::verify_keypair_consistency(SK_PILE, W_PILE, PPUB, ID_PILE_HEX), true);
    check_bool("错误 ID 应失败",
               clpkc::verify_keypair_consistency(SK_PILE, W_PILE, PPUB, ID_CLOUD_HEX), false);

    // --- KAT-9 会话密钥 ---
    std::printf("[KAT-9] derive_session_key + session_key_to_sm4\n");
    std::string sk_pile_side =
        clpkc::derive_session_key(EPH_B, RA, RA, RB, ID_CLOUD_HEX, ID_PILE_HEX, NONCE);
    std::string sk_cloud_side =
        clpkc::derive_session_key(EPH_A, RB, RA, RB, ID_CLOUD_HEX, ID_PILE_HEX, NONCE);
    check("桩侧 derive_session_key", sk_pile_side, SESS_KEY);
    check("云侧 derive_session_key（应相等）", sk_cloud_side, SESS_KEY);
    check("session_key_to_sm4（前 16 字节）", clpkc::session_key_to_sm4(SESS_KEY), SM4_KEY);

    // --- KAT-10 验云端(响应方)签名：签名由 Java 产出，此处由 C++ 验证 ---
    std::printf("[KAT-10] verify_responder（验 Java 产出的签名）\n");
    check_bool("Java 响应方签名 → C++ 验签通过",
               clpkc::verify_responder(RA, RB, ID_CLOUD_HEX, W_CLOUD, NONCE, SIG_RESPONDER, PK_CLOUD),
               true);
    check_bool("篡改 nonce 应失败",
               clpkc::verify_responder(RA, RB, ID_CLOUD_HEX, W_CLOUD,
                                       "0102030405060708090a0b0c0d0e0fff", SIG_RESPONDER, PK_CLOUD),
               false);
    check_bool("篡改签名应失败",
               clpkc::verify_responder(RA, RB, ID_CLOUD_HEX, W_CLOUD, NONCE,
                                       std::string(128, '0'), PK_CLOUD),
               false);
    check_bool("错误公钥应失败",
               clpkc::verify_responder(RA, RB, ID_CLOUD_HEX, W_CLOUD, NONCE, SIG_RESPONDER, PK_PILE),
               false);

    // --- KAT-11 发起方签名 往返（SM2 含随机 k，故只验往返而非固定值）---
    std::printf("[KAT-11] sign_initiator → verify_initiator 往返\n");
    std::string sig = clpkc::sign_initiator(RB, ID_PILE_HEX, W_PILE, NONCE, SK_PILE);
    check_bool("签名长度 128 hex", sig.size() == 128, true);
    check_bool("自验通过",
               clpkc::verify_initiator(RB, ID_PILE_HEX, W_PILE, NONCE, sig, PK_PILE), true);
    check_bool("篡改 nonce 应失败",
               clpkc::verify_initiator(RB, ID_PILE_HEX, W_PILE,
                                       "0102030405060708090a0b0c0d0e0fff", sig, PK_PILE), false);

    // --- KAT-12 随机与密钥生成 sanity ---
    std::printf("[KAT-12] generate_keypair / random_bytes_hex\n");
    clpkc::KeyPair kp = clpkc::generate_keypair();
    check_bool("私钥 64 hex", kp.secret_hex.size() == 64, true);
    check_bool("公钥 128 hex", kp.public_hex.size() == 128, true);
    check_bool("random_bytes_hex(16) 长度 32", clpkc::random_bytes_hex(16).size() == 32, true);
    check_bool("两次随机不相等", clpkc::random_bytes_hex(16) != clpkc::random_bytes_hex(16), true);

    // --- KAT-13 错误处理 ---
    std::printf("[KAT-13] 错误处理（非法入参抛 clpkc::Error）\n");
    bool threw = false;
    try {
        clpkc::reconstruct_full_public("00", W_PILE, PPUB);  // ID 长度非法
    } catch (const clpkc::Error&) {
        threw = true;
    }
    check_bool("非法 ID 长度抛 Error", threw, true);
    threw = false;
    try {
        clpkc::session_key_to_sm4("abcd");  // 会话密钥长度非法
    } catch (const clpkc::Error&) {
        threw = true;
    }
    check_bool("非法会话密钥长度抛 Error", threw, true);

    std::printf("\n=== 结果: %d 通过, %d 失败 ===\n", g_pass, g_fail);
    if (g_fail == 0) {
        // 供反向交叉验证：把该签名交给 Java verifyInitiator 校验（见 kat.md）
        std::printf("\n[交叉验证用] C++ 产出的 initiator 签名:\n%s\n", sig.c_str());
    }
    return g_fail == 0 ? 0 : 1;
}
