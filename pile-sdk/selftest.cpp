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
const std::string MS_HEX =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const std::string UA_PILE =
    "1122334455667788990011223344556677889900112233445566778899001122";
const std::string UA_CLOUD =
    "2233445566778899001122334455667788990011223344556677889900112233";
const std::string EPH_B =
    "3344556677889900112233445566778899001122334455667788990011223344";
const std::string EPH_A =
    "4455667788990011223344556677889900112233445566778899001122334455";
const std::string NONCE =
    "0102030405060708090a0b0c0d0e0f10";
const std::string PSK =
    "00112233445566778899aabbccddeeff";

// 由固定标量确定性导出（Java/C++ 一致，跨运行稳定）
const std::string PPUB =
    "344081b80805540a38d71d721bd072d8957eae15aeb852e72086ab4c5962b89b5bb8628b9d9c4edd30f341a5a25886c063cff46dc04c7e68f2efb3b58830e0f3";
const std::string RB =
    "d7bddda6449033e3202e9d1633d28584b23624c77f0091c745e5c8c7fc13df8a91e03e64c5646c62deb6f12dd80a699c2c61b95c80a768a991d7e6df292e0a63";
const std::string RA =
    "d362a0cb4932a4beba9f1fd22879ffe0e2ffaf65987aaa19b1a4e7d5877be3db844fbdf0065ffcaa35111ccdb9b1321941d907b23f3cf19852fec8b5b4881d22";

// KGC 颁发/云端签名含随机 w/k，冻结进 KAT 作为输入
const std::string W_PILE =
    "e19562f61b4a2befece57ae868322b80b97ee8bcf32e600524446636ffc5b1419edf41dc326d04460fff721d3a77103ff0446a412069d3e473ab57a0ed7e9d88";
const std::string CIPHER_PILE =
    "04612b15de497c992f4665dbb7b0e4555913cedbe3e8e26914b917c24573d65653f1162a4b9e508e261f863cf40f38087d9a5f9801637028d3aab01c1d919eaaa2fba908442cf18bd76104fa4d0e23fe57fb7e4beb55f70a57c7cf7853ee036df20dc39390de77301f1dae228c01afe25dbbc11fdbfc6bcb777705c1c5eff9c597";
const std::string W_CLOUD =
    "513766cab63b2c6a4bd2ba643ecda4b54da3b941f46434af3a7427bd8fa2d75bc7c064dcf63a149f82f281c65cac8cc25810ff5a7359ea4a068c4fa85a29d983";
const std::string SIG_RESPONDER =
    "85d9004a1a7a86798cb6f43471f5bde88f70e228ba4740bd8e8d5f364c1f96a425e2356913cfed174d534636574cdbfafd3012600b885e75c5e13ddc9e6ca966";

// ---------------- KAT 期望输出（Java 交叉验证一致）----------------
const std::string ID_PILE_HEX =
    "70696c652d303031000000000000000000000000000000000000000000000000";
const std::string ID_CLOUD_HEX =
    "636c6f75642d3030310000000000000000000000000000000000000000000000";
const std::string ID_BCD_HEX =
    "0000000000000100000000000000000000000000000000000000000000000000";
const std::string T_PILE =
    "c3d327ec98da76f2bd7dc2cef6d0bd016ab7ffe0d4e92edbe8d8408d2095f3dd";
const std::string SK_PILE =
    "d4f55b30ee40ee7b567dd3f12a151267e24098e0e60b62203e3eb815b99604ff";
const std::string PK_PILE =
    "e05de511ca340f30dfa686f98a4b4fbf0f8c080b22ce7527e8640805db3dbb40d7d421d170566b7e0f550458ce8046092f6be3164c32bfc2080ab392b0182d23";
const std::string PK_CLOUD =
    "b1611e3a53ed78714ed8693b70f90bf7c6435e15250d8f2c130bfa3cf5cb46b424ba107e364c097dc26628297bb02705bd86cdaab5b487695816dbb7363dfbed";
const std::string HMAC_EXP =
    "d0d51b9c7f0c8939775ecf3f5a5a49fdc349dfda5d34a168e6084a84af2f7b12";
const std::string SM3_ABC =
    "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0";
const std::string SESS_KEY =
    "5327df76e796b34f9ba804d987c0748628859631ab8e0a53cb5d9618a8eaea80";
const std::string SM4_KEY =
    "5327df76e796b34f9ba804d987c07486";

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
