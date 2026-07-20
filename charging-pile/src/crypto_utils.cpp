#include "crypto_utils.h"

#include <openssl/core_names.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/obj_mac.h>
#include <openssl/param_build.h>
#include <openssl/rand.h>

#include <cstring>
#include <memory>
#include <stdexcept>

#include "logging.h"

namespace {
using BnPtr = std::unique_ptr<BIGNUM, decltype(&BN_free)>;
using PointPtr = std::unique_ptr<EC_POINT, decltype(&EC_POINT_free)>;

std::vector<unsigned char> be32(unsigned int v) {
    return {static_cast<unsigned char>((v >> 24) & 0xff), static_cast<unsigned char>((v >> 16) & 0xff),
            static_cast<unsigned char>((v >> 8) & 0xff), static_cast<unsigned char>(v & 0xff)};
}

// 用 pub(SEC1) + 可空 priv 构建 SM2 类型 EVP_PKEY
EVP_PKEY* make_sm2_pkey(const std::vector<unsigned char>& pub_sec1, const BIGNUM* priv) {
    OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
    if (!bld) {
        throw std::runtime_error("OSSL_PARAM_BLD_new 失败");
    }
    OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, "SM2", 0);
    OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, pub_sec1.data(), pub_sec1.size());
    if (priv) {
        OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY, priv);
    }
    OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(bld);
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "SM2", nullptr);
    EVP_PKEY* pkey = nullptr;
    int ok = ctx && params && EVP_PKEY_fromdata_init(ctx) > 0
        && EVP_PKEY_fromdata(ctx, &pkey, priv ? EVP_PKEY_KEYPAIR : EVP_PKEY_PUBLIC_KEY, params) > 0;
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    if (!ok || !pkey) {
        if (pkey) EVP_PKEY_free(pkey);
        throw std::runtime_error("构建 SM2 EVP_PKEY 失败");
    }
    return pkey;
}

// DER 编码的 SM2 签名 → 裸 r‖s（各 32 字节大端，共 64 字节）
std::vector<unsigned char> ecdsa_der_to_raw(const std::vector<unsigned char>& der) {
    const unsigned char* p = der.data();
    ECDSA_SIG* sig = d2i_ECDSA_SIG(nullptr, &p, static_cast<long>(der.size()));
    if (!sig) {
        throw std::runtime_error("SM2 签名 DER 解析失败");
    }
    const BIGNUM* r = nullptr;
    const BIGNUM* s = nullptr;
    ECDSA_SIG_get0(sig, &r, &s);
    std::vector<unsigned char> out(64, 0);
    BN_bn2binpad(r, out.data(), 32);
    BN_bn2binpad(s, out.data() + 32, 32);
    ECDSA_SIG_free(sig);
    return out;
}

// 裸 r‖s（64 字节）→ DER 编码（供 OpenSSL EVP 验签）
std::vector<unsigned char> ecdsa_raw_to_der(const std::vector<unsigned char>& raw) {
    if (raw.size() != 64) {
        throw std::runtime_error("SM2 裸签名必须为 64 字节 r‖s");
    }
    ECDSA_SIG* sig = ECDSA_SIG_new();
    BIGNUM* r = BN_bin2bn(raw.data(), 32, nullptr);
    BIGNUM* s = BN_bin2bn(raw.data() + 32, 32, nullptr);
    if (!sig || !r || !s || ECDSA_SIG_set0(sig, r, s) != 1) {
        if (r) BN_free(r);
        if (s) BN_free(s);
        if (sig) ECDSA_SIG_free(sig);
        throw std::runtime_error("构造 ECDSA_SIG 失败");
    }
    int len = i2d_ECDSA_SIG(sig, nullptr);
    std::vector<unsigned char> der(static_cast<std::size_t>(len));
    unsigned char* p = der.data();
    i2d_ECDSA_SIG(sig, &p);
    ECDSA_SIG_free(sig);
    return der;
}
}  // namespace

CryptoUtils::CryptoUtils() {
    group_ = EC_GROUP_new_by_curve_name(NID_sm2);
    ctx_ = BN_CTX_new();
    order_ = BN_new();
    if (!group_ || !ctx_ || !order_) {
        throw std::runtime_error("OpenSSL SM2 EC 初始化失败");
    }
    EC_GROUP_get_order(group_, order_, ctx_);
}

CryptoUtils::~CryptoUtils() {
    BN_free(order_);
    BN_CTX_free(ctx_);
    EC_GROUP_free(group_);
}

KeyMaterial CryptoUtils::generate_static_key() {
    BnPtr x(random_scalar(), BN_free);
    PointPtr p(EC_POINT_new(group_), EC_POINT_free);
    EC_POINT_mul(group_, p.get(), x.get(), nullptr, nullptr, ctx_);
    return {bn_to_fixed_hex(x.get()), point_to_xy_hex(p.get())};
}

std::string CryptoUtils::compose_full_private(const std::string& secret_hex, const std::string& encrypted_partial_hex) {
    std::string ta_hex = sm2_decrypt_c1c3c2(encrypted_partial_hex, secret_hex);
    BnPtr ta(hex_to_bn(ta_hex), BN_free);
    BnPtr ua(hex_to_bn(secret_hex), BN_free);
    BnPtr out(BN_new(), BN_free);
    BN_mod_add(out.get(), ta.get(), ua.get(), order_, ctx_);
    return bn_to_fixed_hex(out.get());
}

std::string CryptoUtils::reconstruct_full_public(const std::string& id, const std::string& claimed_public_hex,
                                                 const std::string& master_public_hex) {
    PointPtr wa(point_from_xy_hex(claimed_public_hex), EC_POINT_free);
    PointPtr ppub(point_from_xy_hex(master_public_hex), EC_POINT_free);
    auto ha = compute_ha(id, master_public_hex);
    BnPtr lambda(compute_lambda(wa.get(), ha), BN_free);
    PointPtr tmp(EC_POINT_new(group_), EC_POINT_free);
    EC_POINT_mul(group_, tmp.get(), nullptr, ppub.get(), lambda.get(), ctx_);  // λ·Ppub
    PointPtr pa(EC_POINT_new(group_), EC_POINT_free);
    EC_POINT_add(group_, pa.get(), wa.get(), tmp.get(), ctx_);                  // WA + λ·Ppub
    return point_to_xy_hex(pa.get());
}

// ---------------------------------------------------------------------------
// 手动 SM2 C1C3C2 解密
// ---------------------------------------------------------------------------
std::string CryptoUtils::sm2_decrypt_c1c3c2(const std::string& cipher_hex, const std::string& secret_hex) {
    auto blob = hex_to_bytes(cipher_hex);
    if (blob.size() < 65 + 32) {
        throw std::runtime_error("SM2 密文长度非法");
    }
    std::vector<unsigned char> c1(blob.begin(), blob.begin() + 65);
    std::vector<unsigned char> c3(blob.begin() + 65, blob.begin() + 97);
    std::vector<unsigned char> c2(blob.begin() + 97, blob.end());

    PointPtr c1p(EC_POINT_new(group_), EC_POINT_free);
    if (!EC_POINT_oct2point(group_, c1p.get(), c1.data(), c1.size(), ctx_)
        || EC_POINT_is_on_curve(group_, c1p.get(), ctx_) != 1) {
        throw std::runtime_error("SM2 C1 点非法");
    }
    BnPtr d(hex_to_bn(secret_hex), BN_free);
    PointPtr s(EC_POINT_new(group_), EC_POINT_free);
    EC_POINT_mul(group_, s.get(), nullptr, c1p.get(), d.get(), ctx_);  // S = d·C1
    BnPtr sx(BN_new(), BN_free);
    BnPtr sy(BN_new(), BN_free);
    EC_POINT_get_affine_coordinates(group_, s.get(), sx.get(), sy.get(), ctx_);
    auto x2 = coord_bytes(sx.get());
    auto y2 = coord_bytes(sy.get());

    // KDF(x2‖y2, len(C2))，GM/T 0003：ct 从 1 起，SM3(Z‖ct_be32)
    std::vector<unsigned char> z = x2;
    z.insert(z.end(), y2.begin(), y2.end());
    std::vector<unsigned char> t;
    unsigned int ct = 1;
    while (t.size() < c2.size()) {
        std::vector<unsigned char> in = z;
        auto ctb = be32(ct++);
        in.insert(in.end(), ctb.begin(), ctb.end());
        auto block = sm3(in);
        t.insert(t.end(), block.begin(), block.end());
    }
    std::vector<unsigned char> m(c2.size());
    for (size_t i = 0; i < c2.size(); i++) {
        m[i] = c2[i] ^ t[i];
    }
    // 校验 C3 = SM3(x2 ‖ M ‖ y2)
    std::vector<unsigned char> u_in = x2;
    u_in.insert(u_in.end(), m.begin(), m.end());
    u_in.insert(u_in.end(), y2.begin(), y2.end());
    auto u = sm3(u_in);
    if (u.size() != c3.size() || CRYPTO_memcmp(u.data(), c3.data(), c3.size()) != 0) {
        throw std::runtime_error("SM2 解密 C3 校验失败");
    }
    return bytes_to_hex(m);
}

// ---------------------------------------------------------------------------
// SM2 签名 / 验签（内部走 OpenSSL EVP，签名内部为 DER；对外线上格式为裸 r‖s 64 字节，
// 由 ecdsa_der_to_raw / ecdsa_raw_to_der 在边界互转；id 作 ZA 用户标识）
// ---------------------------------------------------------------------------
// 全定长字段直拼，无长度前缀
std::vector<unsigned char> CryptoUtils::build_transcript(const std::vector<std::vector<unsigned char>>& fields) {
    std::vector<unsigned char> out;
    for (const auto& f : fields) {
        out.insert(out.end(), f.begin(), f.end());
    }
    return out;
}

// ID 定长编码：取 32 字节，右侧 0x00 补齐；超长截断并告警
std::vector<unsigned char> CryptoUtils::id_fixed(const std::string& id) {
    const std::size_t ID_FIXED_LEN = 32;
    std::vector<unsigned char> out(ID_FIXED_LEN, 0x00);
    std::size_t n = id.size() < ID_FIXED_LEN ? id.size() : ID_FIXED_LEN;
    if (id.size() > ID_FIXED_LEN) {
        LOG_WARN("ID 超过 32 字节，已截断用于 transcript/KDF: " + id);
    }
    std::memcpy(out.data(), id.data(), n);
    return out;
}

// 发起方（桩）签名：transcript = R_B ‖ ID_B ‖ W_B ‖ nonce（全定长直拼）
std::string CryptoUtils::sign_initiator(const std::string& r_pile_hex, const std::string& id,
                                        const std::string& w_hex, const std::string& nonce,
                                        const std::string& full_private_hex) {
    auto msg = build_transcript({
        hex_to_bytes(r_pile_hex),
        id_fixed(id),
        hex_to_bytes(w_hex),
        std::vector<unsigned char>(nonce.begin(), nonce.end())});
    return sm2_sign(msg, id, full_private_hex);
}

std::string CryptoUtils::sm2_sign(const std::vector<unsigned char>& msg, const std::string& id,
                                  const std::string& full_private_hex) {
    BnPtr sk(hex_to_bn(full_private_hex), BN_free);
    PointPtr pub(EC_POINT_new(group_), EC_POINT_free);
    EC_POINT_mul(group_, pub.get(), sk.get(), nullptr, nullptr, ctx_);
    auto pub_sec1 = point_to_sec1(pub.get());
    EVP_PKEY* pkey = make_sm2_pkey(pub_sec1, sk.get());
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey_guard(pkey, EVP_PKEY_free);

    EVP_MD_CTX* mctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new(pkey, nullptr);
    if (!mctx || !pctx) {
        if (mctx) EVP_MD_CTX_free(mctx);
        if (pctx) EVP_PKEY_CTX_free(pctx);
        throw std::runtime_error("SM2 sign ctx 创建失败");
    }
    EVP_PKEY_CTX_set1_id(pctx, id.data(), static_cast<int>(id.size()));
    EVP_MD_CTX_set_pkey_ctx(mctx, pctx);
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> mctx_guard(mctx, EVP_MD_CTX_free);

    size_t siglen = 0;
    if (EVP_DigestSignInit(mctx, nullptr, EVP_sm3(), nullptr, pkey) <= 0
        || EVP_DigestSignUpdate(mctx, msg.data(), msg.size()) <= 0
        || EVP_DigestSignFinal(mctx, nullptr, &siglen) <= 0) {
        throw std::runtime_error("SM2 sign 失败");
    }
    std::vector<unsigned char> sig(siglen);
    if (EVP_DigestSignFinal(mctx, sig.data(), &siglen) <= 0) {
        throw std::runtime_error("SM2 sign final 失败");
    }
    sig.resize(siglen);
    return bytes_to_hex(ecdsa_der_to_raw(sig));  // 输出裸 r‖s 64 字节
}

// 验响应方（云）签名：transcript = R_A ‖ R_B ‖ ID_A ‖ W_A ‖ nonce
bool CryptoUtils::verify_responder(const std::string& r_a_hex, const std::string& r_b_hex,
                                   const std::string& id, const std::string& w_hex, const std::string& nonce,
                                   const std::string& sig_raw_hex, const std::string& full_public_hex) {
    auto msg = build_transcript({
        hex_to_bytes(r_a_hex),
        hex_to_bytes(r_b_hex),
        id_fixed(id),
        hex_to_bytes(w_hex),
        std::vector<unsigned char>(nonce.begin(), nonce.end())});
    return sm2_verify(msg, id, sig_raw_hex, full_public_hex);
}

bool CryptoUtils::sm2_verify(const std::vector<unsigned char>& msg, const std::string& id,
                             const std::string& sig_raw_hex, const std::string& full_public_hex) {
    try {
        PointPtr pa(point_from_xy_hex(full_public_hex), EC_POINT_free);
        auto pa_sec1 = point_to_sec1(pa.get());
        EVP_PKEY* pkey = make_sm2_pkey(pa_sec1, nullptr);
        std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey_guard(pkey, EVP_PKEY_free);

        EVP_MD_CTX* mctx = EVP_MD_CTX_new();
        EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new(pkey, nullptr);
        if (!mctx || !pctx) {
            if (mctx) EVP_MD_CTX_free(mctx);
            if (pctx) EVP_PKEY_CTX_free(pctx);
            return false;
        }
        EVP_PKEY_CTX_set1_id(pctx, id.data(), static_cast<int>(id.size()));
        EVP_MD_CTX_set_pkey_ctx(mctx, pctx);
        std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> mctx_guard(mctx, EVP_MD_CTX_free);

        auto sig = ecdsa_raw_to_der(hex_to_bytes(sig_raw_hex));  // 裸 r‖s 64 字节 → DER
        if (EVP_DigestVerifyInit(mctx, nullptr, EVP_sm3(), nullptr, pkey) <= 0
            || EVP_DigestVerifyUpdate(mctx, msg.data(), msg.size()) <= 0) {
            return false;
        }
        return EVP_DigestVerifyFinal(mctx, sig.data(), sig.size()) == 1;
    } catch (const std::exception&) {
        return false;
    }
}

// ---------------------------------------------------------------------------
// 会话密钥（SM3）
// ---------------------------------------------------------------------------
std::string CryptoUtils::derive_session_key(const std::string& eph_secret_hex, const std::string& peer_point_hex,
                                            const std::string& ra_hex, const std::string& rb_hex,
                                            const std::string& ida, const std::string& idb,
                                            const std::string& nonce) {
    BnPtr a(hex_to_bn(eph_secret_hex), BN_free);
    PointPtr peer(point_from_xy_hex(peer_point_hex), EC_POINT_free);
    PointPtr shared(EC_POINT_new(group_), EC_POINT_free);
    EC_POINT_mul(group_, shared.get(), nullptr, peer.get(), a.get(), ctx_);
    BnPtr sx(BN_new(), BN_free);
    BnPtr sy(BN_new(), BN_free);
    EC_POINT_get_affine_coordinates(group_, shared.get(), sx.get(), sy.get(), ctx_);

    // SK = SM3( Sx ‖ R_A ‖ R_B ‖ ID_A ‖ ID_B ‖ nonce )，全定长字段直拼、单次 SM3
    std::vector<unsigned char> z = build_transcript({
        coord_bytes(sx.get()),
        hex_to_bytes(ra_hex),
        hex_to_bytes(rb_hex),
        id_fixed(ida),
        id_fixed(idb),
        std::vector<unsigned char>(nonce.begin(), nonce.end())});
    return bytes_to_hex(sm3(z));
}

std::string CryptoUtils::hmac_sm3_hex(const std::string& key_hex, const std::string& data_hex) {
    auto key = hex_to_bytes(key_hex);
    auto data = hex_to_bytes(data_hex);
    unsigned int len = 0;
    std::vector<unsigned char> out(EVP_MAX_MD_SIZE);
    HMAC(EVP_sm3(), key.data(), static_cast<int>(key.size()), data.data(), data.size(), out.data(), &len);
    out.resize(len);
    return bytes_to_hex(out);
}

bool CryptoUtils::hmac_sm3_verify(const std::string& key_hex, const std::string& data_hex,
                                  const std::string& expected_mac_hex) {
    std::string actual = hmac_sm3_hex(key_hex, data_hex);
    if (actual.size() != expected_mac_hex.size()) {
        return false;
    }
    return CRYPTO_memcmp(actual.data(), expected_mac_hex.data(), actual.size()) == 0;
}

std::string CryptoUtils::sm3_hex_of_ascii(const std::string& ascii) const {
    std::vector<unsigned char> bytes(ascii.begin(), ascii.end());
    return bytes_to_hex(sm3(bytes));
}

// ---------------------------------------------------------------------------
// HA / λ
// ---------------------------------------------------------------------------
std::vector<unsigned char> CryptoUtils::compute_ha(const std::string& id, const std::string& master_public_hex) const {
    std::vector<unsigned char> idb(id.begin(), id.end());
    unsigned int lenBits = static_cast<unsigned int>(idb.size()) * 8;
    std::vector<unsigned char> input = {static_cast<unsigned char>((lenBits >> 8) & 0xff),
                                        static_cast<unsigned char>(lenBits & 0xff)};
    input.insert(input.end(), idb.begin(), idb.end());

    BnPtr a(BN_new(), BN_free), b(BN_new(), BN_free), p(BN_new(), BN_free);
    EC_GROUP_get_curve(group_, p.get(), a.get(), b.get(), ctx_);
    auto ab = coord_bytes(a.get());
    auto bb = coord_bytes(b.get());
    input.insert(input.end(), ab.begin(), ab.end());
    input.insert(input.end(), bb.begin(), bb.end());

    const EC_POINT* g = EC_GROUP_get0_generator(group_);
    BnPtr gx(BN_new(), BN_free), gy(BN_new(), BN_free);
    EC_POINT_get_affine_coordinates(group_, g, gx.get(), gy.get(), ctx_);
    auto gxb = coord_bytes(gx.get());
    auto gyb = coord_bytes(gy.get());
    input.insert(input.end(), gxb.begin(), gxb.end());
    input.insert(input.end(), gyb.begin(), gyb.end());

    auto ppub = hex_to_bytes(master_public_hex);  // 64 字节 x‖y
    input.insert(input.end(), ppub.begin(), ppub.end());
    return sm3(input);
}

BIGNUM* CryptoUtils::compute_lambda(const EC_POINT* wa, const std::vector<unsigned char>& ha) const {
    BnPtr wx(BN_new(), BN_free), wy(BN_new(), BN_free);
    EC_POINT_get_affine_coordinates(group_, wa, wx.get(), wy.get(), ctx_);
    std::vector<unsigned char> input = coord_bytes(wx.get());
    auto wyb = coord_bytes(wy.get());
    input.insert(input.end(), wyb.begin(), wyb.end());
    input.insert(input.end(), ha.begin(), ha.end());
    auto d = sm3(input);
    return BN_bin2bn(d.data(), static_cast<int>(d.size()), nullptr);
}

// 生成 n 字节随机数并返回 hex（握手 nonce 用，CSPRNG）
std::string CryptoUtils::random_bytes_hex(int n_bytes) {
    std::vector<unsigned char> buf(static_cast<std::size_t>(n_bytes));
    if (RAND_bytes(buf.data(), n_bytes) != 1) {
        throw std::runtime_error("随机数生成失败");
    }
    return bytes_to_hex(buf);
}

// ---------------------------- 点 / 编码辅助 ----------------------------

std::string CryptoUtils::point_to_xy_hex(const EC_POINT* point) const {
    BnPtr x(BN_new(), BN_free), y(BN_new(), BN_free);
    EC_POINT_get_affine_coordinates(group_, point, x.get(), y.get(), ctx_);
    std::vector<unsigned char> out = coord_bytes(x.get());
    auto yb = coord_bytes(y.get());
    out.insert(out.end(), yb.begin(), yb.end());
    return bytes_to_hex(out);
}

EC_POINT* CryptoUtils::point_from_xy_hex(const std::string& hex) const {
    auto bytes = hex_to_bytes(hex);
    if (bytes.size() != 64) {
        throw std::runtime_error("点必须为 64 字节 x‖y");
    }
    BnPtr x(BN_bin2bn(bytes.data(), 32, nullptr), BN_free);
    BnPtr y(BN_bin2bn(bytes.data() + 32, 32, nullptr), BN_free);
    EC_POINT* point = EC_POINT_new(group_);
    if (!EC_POINT_set_affine_coordinates(group_, point, x.get(), y.get(), ctx_)
        || EC_POINT_is_on_curve(group_, point, ctx_) != 1) {
        EC_POINT_free(point);
        throw std::runtime_error("点不在曲线上");
    }
    return point;
}

std::vector<unsigned char> CryptoUtils::point_to_sec1(const EC_POINT* point) const {
    std::vector<unsigned char> out(65);
    size_t len = EC_POINT_point2oct(group_, point, POINT_CONVERSION_UNCOMPRESSED, out.data(), out.size(), ctx_);
    out.resize(len);
    return out;
}

std::vector<unsigned char> CryptoUtils::coord_bytes(const BIGNUM* v) const {
    std::vector<unsigned char> out(32);
    BN_bn2binpad(v, out.data(), 32);
    return out;
}

std::string CryptoUtils::bn_to_fixed_hex(const BIGNUM* bn) const {
    return bytes_to_hex(coord_bytes(bn));
}

BIGNUM* CryptoUtils::hex_to_bn(const std::string& hex) const {
    BIGNUM* bn = nullptr;
    BN_hex2bn(&bn, hex.c_str());
    return bn;
}

std::vector<unsigned char> CryptoUtils::hex_to_bytes(const std::string& hex) const {
    if (hex.size() % 2 != 0) {
        throw std::runtime_error("hex 长度必须为偶数");
    }
    std::vector<unsigned char> out;
    out.reserve(hex.size() / 2);
    for (std::size_t i = 0; i < hex.size(); i += 2) {
        out.push_back(static_cast<unsigned char>(std::stoul(hex.substr(i, 2), nullptr, 16)));
    }
    return out;
}

std::string CryptoUtils::bytes_to_hex(const std::vector<unsigned char>& data) const {
    static const char* digits = "0123456789abcdef";
    std::string out;
    out.reserve(data.size() * 2);
    for (unsigned char c : data) {
        out.push_back(digits[c >> 4]);
        out.push_back(digits[c & 0x0f]);
    }
    return out;
}

std::vector<unsigned char> CryptoUtils::sm3(const std::vector<unsigned char>& data) const {
    std::vector<unsigned char> out(EVP_MAX_MD_SIZE);
    unsigned int len = 0;
    if (EVP_Digest(data.data(), data.size(), out.data(), &len, EVP_sm3(), nullptr) != 1) {
        throw std::runtime_error("SM3 计算失败");
    }
    out.resize(len);
    return out;
}

BIGNUM* CryptoUtils::random_scalar() const {
    BIGNUM* out = BN_new();
    do {
        BN_rand_range(out, order_);
    } while (BN_is_zero(out));
    return out;
}
