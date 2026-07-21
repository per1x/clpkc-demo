#include "clpkc_sdk.h"

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/obj_mac.h>
#include <openssl/param_build.h>
#include <openssl/rand.h>

#include <cstring>
#include <memory>
#include <vector>

namespace clpkc {
namespace {

using Bytes = std::vector<unsigned char>;
using BnPtr = std::unique_ptr<BIGNUM, decltype(&BN_free)>;
using PointPtr = std::unique_ptr<EC_POINT, decltype(&EC_POINT_free)>;

constexpr std::size_t ID_LEN = 32;      // ID 定长 32 字节
constexpr std::size_t SCALAR_LEN = 32;  // 标量/坐标定长 32 字节
constexpr std::size_t POINT_LEN = 64;   // 裸点 X‖Y
constexpr std::size_t SIG_LEN = 64;     // 裸签名 r‖s

// SM2 曲线上下文。每次调用构造/析构 → 无全局状态、天然线程安全。
struct Curve {
    EC_GROUP* group = nullptr;
    BN_CTX* ctx = nullptr;
    BIGNUM* order = nullptr;

    Curve() {
        group = EC_GROUP_new_by_curve_name(NID_sm2);
        ctx = BN_CTX_new();
        order = BN_new();
        if (!group || !ctx || !order) {
            cleanup();
            throw Error("OpenSSL SM2 EC 初始化失败");
        }
        EC_GROUP_get_order(group, order, ctx);
    }
    ~Curve() { cleanup(); }
    Curve(const Curve&) = delete;
    Curve& operator=(const Curve&) = delete;

private:
    void cleanup() {
        if (order) BN_free(order);
        if (ctx) BN_CTX_free(ctx);
        if (group) EC_GROUP_free(group);
        order = nullptr;
        ctx = nullptr;
        group = nullptr;
    }
};

int hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    throw Error("非法 hex 字符");
}

Bytes hex_to_bytes(const std::string& hex) {
    if (hex.size() % 2 != 0) {
        throw Error("hex 长度必须为偶数");
    }
    Bytes out;
    out.reserve(hex.size() / 2);
    for (std::size_t i = 0; i < hex.size(); i += 2) {
        out.push_back(static_cast<unsigned char>((hex_val(hex[i]) << 4) | hex_val(hex[i + 1])));
    }
    return out;
}

std::string bytes_to_hex(const Bytes& data) {
    static const char* digits = "0123456789abcdef";
    std::string out;
    out.reserve(data.size() * 2);
    for (unsigned char c : data) {
        out.push_back(digits[c >> 4]);
        out.push_back(digits[c & 0x0f]);
    }
    return out;
}

// 定长解码：字节数不符立即报错（避免静默截断/补齐导致跨端不一致）
Bytes hex_fixed(const std::string& hex, std::size_t want, const char* name) {
    Bytes b = hex_to_bytes(hex);
    if (b.size() != want) {
        throw Error(std::string(name) + " 必须为 " + std::to_string(want) + " 字节");
    }
    return b;
}

Bytes sm3(const Bytes& data) {
    Bytes out(EVP_MAX_MD_SIZE);
    unsigned int len = 0;
    if (EVP_Digest(data.data(), data.size(), out.data(), &len, EVP_sm3(), nullptr) != 1) {
        throw Error("SM3 计算失败");
    }
    out.resize(len);
    return out;
}

Bytes coord_bytes(const BIGNUM* v) {
    Bytes out(SCALAR_LEN);
    BN_bn2binpad(v, out.data(), static_cast<int>(SCALAR_LEN));
    return out;
}

std::string bn_to_fixed_hex(const BIGNUM* bn) { return bytes_to_hex(coord_bytes(bn)); }

BIGNUM* hex_to_bn(const std::string& hex) {
    BIGNUM* bn = nullptr;
    if (BN_hex2bn(&bn, hex.c_str()) == 0) {
        if (bn) BN_free(bn);
        throw Error("标量 hex 解析失败");
    }
    return bn;
}

std::string point_to_xy_hex(const Curve& c, const EC_POINT* point) {
    BnPtr x(BN_new(), BN_free), y(BN_new(), BN_free);
    EC_POINT_get_affine_coordinates(c.group, point, x.get(), y.get(), c.ctx);
    Bytes out = coord_bytes(x.get());
    Bytes yb = coord_bytes(y.get());
    out.insert(out.end(), yb.begin(), yb.end());
    return bytes_to_hex(out);
}

EC_POINT* point_from_xy_hex(const Curve& c, const std::string& hex) {
    Bytes bytes = hex_fixed(hex, POINT_LEN, "曲线点");
    BnPtr x(BN_bin2bn(bytes.data(), 32, nullptr), BN_free);
    BnPtr y(BN_bin2bn(bytes.data() + 32, 32, nullptr), BN_free);
    EC_POINT* point = EC_POINT_new(c.group);
    if (!EC_POINT_set_affine_coordinates(c.group, point, x.get(), y.get(), c.ctx)
        || EC_POINT_is_on_curve(c.group, point, c.ctx) != 1) {
        EC_POINT_free(point);
        throw Error("点不在 SM2 曲线上");
    }
    return point;
}

Bytes point_to_sec1(const Curve& c, const EC_POINT* point) {
    Bytes out(65);
    std::size_t len = EC_POINT_point2oct(c.group, point, POINT_CONVERSION_UNCOMPRESSED,
                                         out.data(), out.size(), c.ctx);
    out.resize(len);
    return out;
}

Bytes be32(unsigned int v) {
    return {static_cast<unsigned char>((v >> 24) & 0xff), static_cast<unsigned char>((v >> 16) & 0xff),
            static_cast<unsigned char>((v >> 8) & 0xff), static_cast<unsigned char>(v & 0xff)};
}

// 有序定长字段直拼（无长度前缀）
Bytes concat(const std::vector<Bytes>& fields) {
    Bytes out;
    for (const auto& f : fields) {
        out.insert(out.end(), f.begin(), f.end());
    }
    return out;
}

// nonce 参与 transcript/KDF 时绑定的是其 hex 串的 ASCII 字节（既定互通约定）
Bytes nonce_ascii(const std::string& nonce_hex) {
    return Bytes(nonce_hex.begin(), nonce_hex.end());
}

EVP_PKEY* make_sm2_pkey(const Bytes& pub_sec1, const BIGNUM* priv) {
    OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
    if (!bld) {
        throw Error("OSSL_PARAM_BLD_new 失败");
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
        throw Error("构建 SM2 EVP_PKEY 失败");
    }
    return pkey;
}

// DER → 裸 r‖s（各 32 字节大端）
Bytes ecdsa_der_to_raw(const Bytes& der) {
    const unsigned char* p = der.data();
    ECDSA_SIG* sig = d2i_ECDSA_SIG(nullptr, &p, static_cast<long>(der.size()));
    if (!sig) {
        throw Error("SM2 签名 DER 解析失败");
    }
    const BIGNUM* r = nullptr;
    const BIGNUM* s = nullptr;
    ECDSA_SIG_get0(sig, &r, &s);
    Bytes out(SIG_LEN, 0);
    BN_bn2binpad(r, out.data(), 32);
    BN_bn2binpad(s, out.data() + 32, 32);
    ECDSA_SIG_free(sig);
    return out;
}

// 裸 r‖s（64 字节）→ DER（供 OpenSSL EVP 验签）
Bytes ecdsa_raw_to_der(const Bytes& raw) {
    if (raw.size() != SIG_LEN) {
        throw Error("SM2 裸签名必须为 64 字节 r‖s");
    }
    ECDSA_SIG* sig = ECDSA_SIG_new();
    BIGNUM* r = BN_bin2bn(raw.data(), 32, nullptr);
    BIGNUM* s = BN_bin2bn(raw.data() + 32, 32, nullptr);
    if (!sig || !r || !s || ECDSA_SIG_set0(sig, r, s) != 1) {
        if (r) BN_free(r);
        if (s) BN_free(s);
        if (sig) ECDSA_SIG_free(sig);
        throw Error("构造 ECDSA_SIG 失败");
    }
    int len = i2d_ECDSA_SIG(sig, nullptr);
    Bytes der(static_cast<std::size_t>(len));
    unsigned char* p = der.data();
    i2d_ECDSA_SIG(sig, &p);
    ECDSA_SIG_free(sig);
    return der;
}

// HA = SM3(ENTL(0x0100) ‖ ID32 ‖ a ‖ b ‖ Gx ‖ Gy ‖ Ppub.x ‖ Ppub.y)
Bytes compute_ha(const Curve& c, const Bytes& id32, const std::string& ppub_hex) {
    unsigned int len_bits = static_cast<unsigned int>(id32.size()) * 8;  // = 256 → 0x0100
    Bytes input = {static_cast<unsigned char>((len_bits >> 8) & 0xff),
                   static_cast<unsigned char>(len_bits & 0xff)};
    input.insert(input.end(), id32.begin(), id32.end());

    BnPtr a(BN_new(), BN_free), b(BN_new(), BN_free), p(BN_new(), BN_free);
    EC_GROUP_get_curve(c.group, p.get(), a.get(), b.get(), c.ctx);
    Bytes ab = coord_bytes(a.get());
    Bytes bb = coord_bytes(b.get());
    input.insert(input.end(), ab.begin(), ab.end());
    input.insert(input.end(), bb.begin(), bb.end());

    const EC_POINT* g = EC_GROUP_get0_generator(c.group);
    BnPtr gx(BN_new(), BN_free), gy(BN_new(), BN_free);
    EC_POINT_get_affine_coordinates(c.group, g, gx.get(), gy.get(), c.ctx);
    Bytes gxb = coord_bytes(gx.get());
    Bytes gyb = coord_bytes(gy.get());
    input.insert(input.end(), gxb.begin(), gxb.end());
    input.insert(input.end(), gyb.begin(), gyb.end());

    Bytes ppub = hex_fixed(ppub_hex, POINT_LEN, "Ppub");
    input.insert(input.end(), ppub.begin(), ppub.end());
    return sm3(input);
}

// λ = SM3(W.x ‖ W.y ‖ HA)，按大端无符号整数取用
BIGNUM* compute_lambda(const Curve& c, const EC_POINT* w, const Bytes& ha) {
    BnPtr wx(BN_new(), BN_free), wy(BN_new(), BN_free);
    EC_POINT_get_affine_coordinates(c.group, w, wx.get(), wy.get(), c.ctx);
    Bytes input = coord_bytes(wx.get());
    Bytes wyb = coord_bytes(wy.get());
    input.insert(input.end(), wyb.begin(), wyb.end());
    input.insert(input.end(), ha.begin(), ha.end());
    Bytes d = sm3(input);
    return BN_bin2bn(d.data(), static_cast<int>(d.size()), nullptr);
}

// SM2 签名核心：对已构造好的 transcript 签名，ZA 用 32 字节 ID
std::string sm2_sign(const Bytes& msg, const Bytes& id32, const std::string& sk_hex) {
    Curve c;
    BnPtr sk(hex_to_bn(sk_hex), BN_free);
    PointPtr pub(EC_POINT_new(c.group), EC_POINT_free);
    EC_POINT_mul(c.group, pub.get(), sk.get(), nullptr, nullptr, c.ctx);
    Bytes pub_sec1 = point_to_sec1(c, pub.get());
    EVP_PKEY* pkey = make_sm2_pkey(pub_sec1, sk.get());
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey_guard(pkey, EVP_PKEY_free);

    EVP_MD_CTX* mctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new(pkey, nullptr);
    if (!mctx || !pctx) {
        if (mctx) EVP_MD_CTX_free(mctx);
        if (pctx) EVP_PKEY_CTX_free(pctx);
        throw Error("SM2 sign ctx 创建失败");
    }
    EVP_PKEY_CTX_set1_id(pctx, id32.data(), static_cast<int>(id32.size()));
    EVP_MD_CTX_set_pkey_ctx(mctx, pctx);
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> mctx_guard(mctx, EVP_MD_CTX_free);

    std::size_t siglen = 0;
    if (EVP_DigestSignInit(mctx, nullptr, EVP_sm3(), nullptr, pkey) <= 0
        || EVP_DigestSignUpdate(mctx, msg.data(), msg.size()) <= 0
        || EVP_DigestSignFinal(mctx, nullptr, &siglen) <= 0) {
        throw Error("SM2 sign 失败");
    }
    Bytes sig(siglen);
    if (EVP_DigestSignFinal(mctx, sig.data(), &siglen) <= 0) {
        throw Error("SM2 sign final 失败");
    }
    sig.resize(siglen);
    return bytes_to_hex(ecdsa_der_to_raw(sig));
}

// SM2 验签核心：任何异常一律返回 false
bool sm2_verify(const Bytes& msg, const Bytes& id32, const std::string& sig_raw_hex,
                const std::string& pk_hex) {
    try {
        Curve c;
        PointPtr pk(point_from_xy_hex(c, pk_hex), EC_POINT_free);
        Bytes pk_sec1 = point_to_sec1(c, pk.get());
        EVP_PKEY* pkey = make_sm2_pkey(pk_sec1, nullptr);
        std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey_guard(pkey, EVP_PKEY_free);

        EVP_MD_CTX* mctx = EVP_MD_CTX_new();
        EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new(pkey, nullptr);
        if (!mctx || !pctx) {
            if (mctx) EVP_MD_CTX_free(mctx);
            if (pctx) EVP_PKEY_CTX_free(pctx);
            return false;
        }
        EVP_PKEY_CTX_set1_id(pctx, id32.data(), static_cast<int>(id32.size()));
        EVP_MD_CTX_set_pkey_ctx(mctx, pctx);
        std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> mctx_guard(mctx, EVP_MD_CTX_free);

        Bytes sig = ecdsa_raw_to_der(hex_fixed(sig_raw_hex, SIG_LEN, "签名"));
        if (EVP_DigestVerifyInit(mctx, nullptr, EVP_sm3(), nullptr, pkey) <= 0
            || EVP_DigestVerifyUpdate(mctx, msg.data(), msg.size()) <= 0) {
            return false;
        }
        return EVP_DigestVerifyFinal(mctx, sig.data(), sig.size()) == 1;
    } catch (const std::exception&) {
        return false;
    }
}

}  // namespace

// ===========================================================================
// 1. 密钥与随机数
// ===========================================================================

KeyPair generate_keypair() {
    Curve c;
    BnPtr x(BN_new(), BN_free);
    do {
        if (BN_rand_range(x.get(), c.order) != 1) {
            throw Error("随机标量生成失败");
        }
    } while (BN_is_zero(x.get()));
    PointPtr p(EC_POINT_new(c.group), EC_POINT_free);
    EC_POINT_mul(c.group, p.get(), x.get(), nullptr, nullptr, c.ctx);
    return {bn_to_fixed_hex(x.get()), point_to_xy_hex(c, p.get())};
}

std::string random_bytes_hex(int n_bytes) {
    if (n_bytes <= 0) {
        throw Error("随机字节数必须为正");
    }
    Bytes buf(static_cast<std::size_t>(n_bytes));
    if (RAND_bytes(buf.data(), n_bytes) != 1) {
        throw Error("随机数生成失败");
    }
    return bytes_to_hex(buf);
}

// ===========================================================================
// 2. HMAC-SM3
// ===========================================================================

std::string hmac_sm3_hex(const std::string& key_hex, const std::string& data_hex) {
    Bytes key = hex_to_bytes(key_hex);
    Bytes data = hex_to_bytes(data_hex);
    unsigned int len = 0;
    Bytes out(EVP_MAX_MD_SIZE);
    if (HMAC(EVP_sm3(), key.data(), static_cast<int>(key.size()), data.data(), data.size(),
             out.data(), &len) == nullptr) {
        throw Error("HMAC-SM3 计算失败");
    }
    out.resize(len);
    return bytes_to_hex(out);
}

bool hmac_sm3_verify(const std::string& key_hex, const std::string& data_hex,
                     const std::string& expected_mac_hex) {
    try {
        std::string actual = hmac_sm3_hex(key_hex, data_hex);
        if (actual.size() != expected_mac_hex.size()) {
            return false;
        }
        return CRYPTO_memcmp(actual.data(), expected_mac_hex.data(), actual.size()) == 0;
    } catch (const std::exception&) {
        return false;
    }
}

// ===========================================================================
// 3. 隐式证书
// ===========================================================================

std::string sm2_decrypt(const std::string& d_hex, const std::string& cipher_hex) {
    Curve c;
    Bytes blob = hex_to_bytes(cipher_hex);
    if (blob.size() < 65 + 32) {
        throw Error("SM2 密文长度非法（至少 C1(65)+C3(32)）");
    }
    Bytes c1(blob.begin(), blob.begin() + 65);
    Bytes c3(blob.begin() + 65, blob.begin() + 97);
    Bytes c2(blob.begin() + 97, blob.end());

    PointPtr c1p(EC_POINT_new(c.group), EC_POINT_free);
    if (!EC_POINT_oct2point(c.group, c1p.get(), c1.data(), c1.size(), c.ctx)
        || EC_POINT_is_on_curve(c.group, c1p.get(), c.ctx) != 1) {
        throw Error("SM2 C1 点非法");
    }
    BnPtr d(hex_to_bn(d_hex), BN_free);
    PointPtr s(EC_POINT_new(c.group), EC_POINT_free);
    EC_POINT_mul(c.group, s.get(), nullptr, c1p.get(), d.get(), c.ctx);  // S = d·C1
    BnPtr sx(BN_new(), BN_free), sy(BN_new(), BN_free);
    EC_POINT_get_affine_coordinates(c.group, s.get(), sx.get(), sy.get(), c.ctx);
    Bytes x2 = coord_bytes(sx.get());
    Bytes y2 = coord_bytes(sy.get());

    // KDF(x2‖y2, len(C2))，GM/T 0003：ct 从 1 起，SM3(Z‖ct_be32)
    Bytes z = x2;
    z.insert(z.end(), y2.begin(), y2.end());
    Bytes t;
    unsigned int ct = 1;
    while (t.size() < c2.size()) {
        Bytes in = z;
        Bytes ctb = be32(ct++);
        in.insert(in.end(), ctb.begin(), ctb.end());
        Bytes block = sm3(in);
        t.insert(t.end(), block.begin(), block.end());
    }
    Bytes m(c2.size());
    for (std::size_t i = 0; i < c2.size(); i++) {
        m[i] = c2[i] ^ t[i];
    }
    // 校验 C3 = SM3(x2 ‖ M ‖ y2)
    Bytes u_in = x2;
    u_in.insert(u_in.end(), m.begin(), m.end());
    u_in.insert(u_in.end(), y2.begin(), y2.end());
    Bytes u = sm3(u_in);
    if (u.size() != c3.size() || CRYPTO_memcmp(u.data(), c3.data(), c3.size()) != 0) {
        throw Error("SM2 解密 C3 校验失败");
    }
    return bytes_to_hex(m);
}

std::string compose_full_private(const std::string& d_hex, const std::string& t_hex) {
    Curve c;
    BnPtr d(hex_to_bn(d_hex), BN_free);
    BnPtr t(hex_to_bn(t_hex), BN_free);
    BnPtr out(BN_new(), BN_free);
    BN_mod_add(out.get(), t.get(), d.get(), c.order, c.ctx);
    return bn_to_fixed_hex(out.get());
}

std::string reconstruct_full_public(const std::string& id_hex, const std::string& w_hex,
                                    const std::string& ppub_hex) {
    Curve c;
    Bytes id32 = hex_fixed(id_hex, ID_LEN, "ID");
    PointPtr w(point_from_xy_hex(c, w_hex), EC_POINT_free);
    PointPtr ppub(point_from_xy_hex(c, ppub_hex), EC_POINT_free);
    Bytes ha = compute_ha(c, id32, ppub_hex);
    BnPtr lambda(compute_lambda(c, w.get(), ha), BN_free);
    PointPtr tmp(EC_POINT_new(c.group), EC_POINT_free);
    EC_POINT_mul(c.group, tmp.get(), nullptr, ppub.get(), lambda.get(), c.ctx);  // λ·Ppub
    PointPtr pk(EC_POINT_new(c.group), EC_POINT_free);
    EC_POINT_add(c.group, pk.get(), w.get(), tmp.get(), c.ctx);                  // W + λ·Ppub
    return point_to_xy_hex(c, pk.get());
}

bool verify_keypair_consistency(const std::string& sk_hex, const std::string& w_hex,
                                const std::string& ppub_hex, const std::string& id_hex) {
    try {
        Curve c;
        BnPtr sk(hex_to_bn(sk_hex), BN_free);
        PointPtr lhs(EC_POINT_new(c.group), EC_POINT_free);
        EC_POINT_mul(c.group, lhs.get(), sk.get(), nullptr, nullptr, c.ctx);  // SK·G
        std::string lhs_hex = point_to_xy_hex(c, lhs.get());
        std::string rhs_hex = reconstruct_full_public(id_hex, w_hex, ppub_hex);
        return lhs_hex == rhs_hex;
    } catch (const std::exception&) {
        return false;
    }
}

// ===========================================================================
// 4. 签名 / 验签
// ===========================================================================

std::string sign_initiator(const std::string& rB_hex, const std::string& idB_hex,
                           const std::string& wB_hex, const std::string& nonce_hex,
                           const std::string& sk_hex) {
    Bytes id32 = hex_fixed(idB_hex, ID_LEN, "ID_B");
    Bytes msg = concat({hex_fixed(rB_hex, POINT_LEN, "R_B"), id32,
                        hex_fixed(wB_hex, POINT_LEN, "W_B"), nonce_ascii(nonce_hex)});
    return sm2_sign(msg, id32, sk_hex);
}

bool verify_initiator(const std::string& rB_hex, const std::string& idB_hex,
                      const std::string& wB_hex, const std::string& nonce_hex,
                      const std::string& sig_raw_hex, const std::string& pk_hex) {
    try {
        Bytes id32 = hex_fixed(idB_hex, ID_LEN, "ID_B");
        Bytes msg = concat({hex_fixed(rB_hex, POINT_LEN, "R_B"), id32,
                            hex_fixed(wB_hex, POINT_LEN, "W_B"), nonce_ascii(nonce_hex)});
        return sm2_verify(msg, id32, sig_raw_hex, pk_hex);
    } catch (const std::exception&) {
        return false;
    }
}

bool verify_responder(const std::string& rA_hex, const std::string& rB_hex,
                      const std::string& idA_hex, const std::string& wA_hex,
                      const std::string& nonce_hex, const std::string& sig_raw_hex,
                      const std::string& pk_hex) {
    try {
        Bytes id32 = hex_fixed(idA_hex, ID_LEN, "ID_A");
        Bytes msg = concat({hex_fixed(rA_hex, POINT_LEN, "R_A"), hex_fixed(rB_hex, POINT_LEN, "R_B"),
                            id32, hex_fixed(wA_hex, POINT_LEN, "W_A"), nonce_ascii(nonce_hex)});
        return sm2_verify(msg, id32, sig_raw_hex, pk_hex);
    } catch (const std::exception&) {
        return false;
    }
}

// ===========================================================================
// 5. 会话密钥
// ===========================================================================

std::string derive_session_key(const std::string& eph_secret_hex, const std::string& peer_point_hex,
                               const std::string& rA_hex, const std::string& rB_hex,
                               const std::string& idA_hex, const std::string& idB_hex,
                               const std::string& nonce_hex) {
    Curve c;
    BnPtr a(hex_to_bn(eph_secret_hex), BN_free);
    PointPtr peer(point_from_xy_hex(c, peer_point_hex), EC_POINT_free);
    PointPtr shared(EC_POINT_new(c.group), EC_POINT_free);
    EC_POINT_mul(c.group, shared.get(), nullptr, peer.get(), a.get(), c.ctx);
    BnPtr sx(BN_new(), BN_free), sy(BN_new(), BN_free);
    EC_POINT_get_affine_coordinates(c.group, shared.get(), sx.get(), sy.get(), c.ctx);

    // SK = SM3(Sx ‖ R_A ‖ R_B ‖ ID_A ‖ ID_B ‖ nonce_ascii)，单次 SM3
    Bytes z = concat({coord_bytes(sx.get()),
                      hex_fixed(rA_hex, POINT_LEN, "R_A"),
                      hex_fixed(rB_hex, POINT_LEN, "R_B"),
                      hex_fixed(idA_hex, ID_LEN, "ID_A"),
                      hex_fixed(idB_hex, ID_LEN, "ID_B"),
                      nonce_ascii(nonce_hex)});
    return bytes_to_hex(sm3(z));
}

std::string session_key_to_sm4(const std::string& sk32_hex) {
    Bytes sk = hex_fixed(sk32_hex, 32, "会话密钥");
    return bytes_to_hex(Bytes(sk.begin(), sk.begin() + 16));  // 取前 16 字节
}

// ===========================================================================
// 6. 编码辅助
// ===========================================================================

std::string make_id_from_ascii(const std::string& ascii) {
    if (ascii.size() > ID_LEN) {
        throw Error("ASCII 主机编号超过 32 字节");
    }
    Bytes out(ID_LEN, 0x00);
    std::memcpy(out.data(), ascii.data(), ascii.size());
    return bytes_to_hex(out);
}

std::string make_id_from_bcd(const std::string& bcd_hex) {
    Bytes bcd = hex_fixed(bcd_hex, 7, "BCD 主机编号");
    Bytes out(ID_LEN, 0x00);
    std::memcpy(out.data(), bcd.data(), bcd.size());
    return bytes_to_hex(out);
}

std::string point_to_wire(const std::string& point_hex) {
    Bytes b = hex_to_bytes(point_hex);
    if (b.size() == POINT_LEN) {
        return bytes_to_hex(b);
    }
    if (b.size() == 65 && b[0] == 0x04) {
        return bytes_to_hex(Bytes(b.begin() + 1, b.end()));
    }
    throw Error("点必须为 64 字节裸点或 65 字节 SEC1(04‖X‖Y)");
}

std::string point_from_wire(const std::string& wire_hex) {
    Bytes b = hex_fixed(wire_hex, POINT_LEN, "裸点");
    Bytes out;
    out.reserve(65);
    out.push_back(0x04);
    out.insert(out.end(), b.begin(), b.end());
    return bytes_to_hex(out);
}

std::string sm3_hex(const std::string& data_hex) {
    return bytes_to_hex(sm3(hex_to_bytes(data_hex)));
}

}  // namespace clpkc
