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

// ID：桩=7B BCD 主机编号‖25B 0x00；云=域名 ASCII‖0x00 补齐到 32B
const std::string HOST_NO = "00000000000001";
const std::string CLOUD_DOMAIN  = "cloud.example.com";
const std::string ID_PILE_HEX =
    "0000000000000100000000000000000000000000000000000000000000000000";
const std::string ID_CLOUD_HEX =
    "636c6f75642e6578616d706c652e636f6d000000000000000000000000000000";

// 由固定标量确定性导出
const std::string PPUB =
    "344081b80805540a38d71d721bd072d8957eae15aeb852e72086ab4c5962b89b5bb8628b9d9c4edd30f341a5a25886c063cff46dc04c7e68f2efb3b58830e0f3";
const std::string RB =
    "d7bddda6449033e3202e9d1633d28584b23624c77f0091c745e5c8c7fc13df8a91e03e64c5646c62deb6f12dd80a699c2c61b95c80a768a991d7e6df292e0a63";
const std::string RA =
    "d362a0cb4932a4beba9f1fd22879ffe0e2ffaf65987aaa19b1a4e7d5877be3db844fbdf0065ffcaa35111ccdb9b1321941d907b23f3cf19852fec8b5b4881d22";

// KGC 颁发/云端签名含随机 w/k，冻结进 KAT 作为输入
const std::string W_PILE =
    "c40387e9a0d933cfe840e343ec6df4d227c9901654cdac8186cd1825e4958da5030a5b74e617f483ef688d8b01e6dbd8ae2f6ed102decea8e8b4367f714e6ca9";
const std::string CIPHER_PILE =
    "04403ca4451e324adfd32a792163cb5ae182fbe103698db0743a1289e8bb7205852add214d3520a695b1e40ca34fcfb47c7abbe4fb60edb39cc6de7f2396550738c6a8243be05ed0126af70c5dff6593cbc985769ce563665a8557ef01fbd564fc19f32bd424cbe624681aee11a27f66ce72408eeacc96454697ed0ce2117061b8";
const std::string W_CLOUD =
    "8113fea74d8f3f8ae31139a5fd8f6615a5b18be1802a46785ce2855bd39e94f66735b23e42c640a4707db7a4d4e23a8b8bf5084764e1492ac8c10aefd82a7732";
const std::string SIG_RESPONDER =
    "2e1b8baf6ba142ccf88ddf577463e93896372ce90b2085dd07d4a85f48bf2a327311865d0453be0af2901ff82580306b36bcda790e844210070e3f6de0d0dbc6";

// ---------------- KAT 期望输出（Java 交叉验证一致）----------------
const std::string T_PILE =
    "87ce2bc0c1aeb3a14ed247943c46159d24eb4f09fa779e1363a7fb6e3024a9e2";
const std::string SK_PILE =
    "98f05f0517152b29e7d258b66f8a6b039c73e80a0b99d157b90e72f6c924bb04";
const std::string PK_PILE =
    "ff7c8b38fc23a5412401d4e6f1778cd6e77c3968d0cb3affa25c5e3a4fa539f4b40e16da369641f9a7a6aa91b2046c3506e9f6b02f756bc76f473c462819338e";
const std::string PK_CLOUD =
    "76fe9e59a0d9b95b46f4704086dace3ba4e8a69cdac02f42ab07ddb9b7c518059fc5dc54b6bd21c9600180d0719e02607e8eaa10499ffffe601b4551c989badd";
const std::string HMAC_EXP =
    "d0d51b9c7f0c8939775ecf3f5a5a49fdc349dfda5d34a168e6084a84af2f7b12";
const std::string SM3_ABC =
    "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0";
const std::string SESS_KEY =
    "badd7fb23a583988bda086803c8da5a9b833040df7d77bfb3f68fbffa74e0d00";
const std::string SM4_KEY =
    "badd7fb23a583988bda086803c8da5a9";

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

    // --- KAT-3 ID 构造 ---
    std::printf("[KAT-3] ID 构造：桩 BCD 主机编号 / 云 域名 ASCII\n");
    check("make_id_from_bcd(\"00000000000001\")", clpkc::make_id_from_bcd(HOST_NO), ID_PILE_HEX);
    check("make_id_from_bcd(\"1\") 左补0 等价", clpkc::make_id_from_bcd("1"), ID_PILE_HEX);
    check("make_id_from_ascii(域名)", clpkc::make_id_from_ascii(CLOUD_DOMAIN), ID_CLOUD_HEX);
    {
        bool t = false;
        try { clpkc::make_id_from_bcd("123456789012345"); } catch (const clpkc::Error&) { t = true; }
        check_bool("主机编号超 14 位应报错", t, true);
        t = false;
        try { clpkc::make_id_from_bcd("12a4"); } catch (const clpkc::Error&) { t = true; }
        check_bool("主机编号含非十进制字符应报错", t, true);
        t = false;
        try { clpkc::make_id_from_ascii(std::string(33, 'x')); } catch (const clpkc::Error&) { t = true; }
        check_bool("ASCII ID 超 32 字节应报错", t, true);
    }

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
