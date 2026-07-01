#include "crypto_utils.h"

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/param_build.h>
#include <openssl/rand.h>

#include <memory>
#include <stdexcept>

namespace {
using BnPtr = std::unique_ptr<BIGNUM, decltype(&BN_free)>;
using PointPtr = std::unique_ptr<EC_POINT, decltype(&EC_POINT_free)>;
}

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

// ---------------------------------------------------------------------------
// 内部：SM2 EVP_PKEY 构建
// ---------------------------------------------------------------------------
namespace {

std::vector<unsigned char> pub_bytes_from_priv(EC_GROUP* group, BN_CTX* ctx, const BIGNUM* d) {
    PointPtr p(EC_POINT_new(group), EC_POINT_free);
    EC_POINT_mul(group, p.get(), d, nullptr, nullptr, ctx);
    std::vector<unsigned char> out(65);
    size_t len = EC_POINT_point2oct(group, p.get(), POINT_CONVERSION_UNCOMPRESSED, out.data(), out.size(), ctx);
    out.resize(len);
    return out;
}

// 用 pub(必需) + priv(可空) 构建 SM2 类型 EVP_PKEY。失败抛异常。
EVP_PKEY* make_sm2_pkey(const std::vector<unsigned char>& pub, const BIGNUM* priv) {
    OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
    if (!bld) {
        throw std::runtime_error("OSSL_PARAM_BLD_new 失败");
    }
    OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, "SM2", 0);
    OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, pub.data(), pub.size());
    if (priv) {
        OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY, priv);
    }
    OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(bld);
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "SM2", nullptr);
    EVP_PKEY* pkey = nullptr;
    int ok = ctx && params
        && EVP_PKEY_fromdata_init(ctx) > 0
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

}  // namespace

// ---------------------------------------------------------------------------
KeyMaterial CryptoUtils::generate_static_key() {
    BnPtr x(random_scalar(), BN_free);
    PointPtr p(EC_POINT_new(group_), EC_POINT_free);
    EC_POINT_mul(group_, p.get(), x.get(), nullptr, nullptr, ctx_);
    return {bn_to_fixed_hex(x.get()), bytes_to_hex(point_to_bytes(p.get()))};
}

std::string CryptoUtils::compose_full_private(const std::string& secret_hex, const std::string& partial_hex) {
    std::string d_hex = hash_point_to_scalar(partial_hex);
    BnPtr x(hex_to_bn(secret_hex), BN_free);
    BnPtr d(hex_to_bn(d_hex), BN_free);
    BnPtr out(BN_new(), BN_free);
    BN_mod_add(out.get(), x.get(), d.get(), order_, ctx_);
    return bn_to_fixed_hex(out.get());
}

std::string CryptoUtils::compute_derived_public(const std::string& point_hex) {
    std::string d_hex = hash_point_to_scalar(point_hex);
    BnPtr d(hex_to_bn(d_hex), BN_free);
    PointPtr y(EC_POINT_new(group_), EC_POINT_free);
    EC_POINT_mul(group_, y.get(), d.get(), nullptr, nullptr, ctx_);
    return bytes_to_hex(point_to_bytes(y.get()));
}

std::string CryptoUtils::hash_point_to_scalar(const std::string& point_hex) const {
    auto point_bytes = hex_to_bytes(point_hex);
    if (point_bytes.size() != 65 || point_bytes[0] != 0x04) {
        throw std::runtime_error("hash_point_to_scalar: 非法 SEC1 点");
    }
    std::vector<unsigned char> coords(point_bytes.begin() + 1, point_bytes.end());
    auto digest = sm3(coords);
    BnPtr out(BN_bin2bn(digest.data(), static_cast<int>(digest.size()), nullptr), BN_free);
    BN_mod(out.get(), out.get(), order_, ctx_);
    if (BN_is_zero(out.get())) { BN_one(out.get()); }
    return bn_to_fixed_hex(out.get());
}

std::string CryptoUtils::derive_full_public(const std::string& public_hex, const std::string& derived_public_hex) {
    PointPtr p(point_from_hex(public_hex), EC_POINT_free);
    PointPtr y(point_from_hex(derived_public_hex), EC_POINT_free);
    PointPtr full(EC_POINT_new(group_), EC_POINT_free);
    EC_POINT_add(group_, full.get(), p.get(), y.get(), ctx_);
    return bytes_to_hex(point_to_bytes(full.get()));
}

// ---------------------------------------------------------------------------
// SM2 签名 / 验签（DER；id 作为 ZA 用户标识）
// ---------------------------------------------------------------------------
std::string CryptoUtils::sign_transcript(const std::string& ra_hex, const std::string& id, const std::string& wb_hex,
                                         const std::string& nonce, const std::string& full_private_hex) {
    auto msg = transcript(ra_hex, id, wb_hex, nonce);
    BnPtr sk(hex_to_bn(full_private_hex), BN_free);
    auto pub = pub_bytes_from_priv(group_, ctx_, sk.get());
    EVP_PKEY* pkey = make_sm2_pkey(pub, sk.get());
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey_guard(pkey, EVP_PKEY_free);

    EVP_MD_CTX* mctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new(pkey, nullptr);
    if (!mctx || !pctx) {
        if (mctx) EVP_MD_CTX_free(mctx);
        if (pctx) EVP_PKEY_CTX_free(pctx);
        throw std::runtime_error("SM2 sign ctx 创建失败");
    }
    EVP_PKEY_CTX_set1_id(pctx, id.data(), static_cast<int>(id.size()));
    EVP_MD_CTX_set_pkey_ctx(mctx, pctx);  // mctx 接管 pctx
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> mctx_guard(mctx, EVP_MD_CTX_free);

    size_t siglen = 0;
    std::vector<unsigned char> sig;
    if (EVP_DigestSignInit(mctx, nullptr, EVP_sm3(), nullptr, pkey) <= 0
        || EVP_DigestSignUpdate(mctx, msg.data(), msg.size()) <= 0
        || EVP_DigestSignFinal(mctx, nullptr, &siglen) <= 0) {
        throw std::runtime_error("SM2 sign 失败");
    }
    sig.resize(siglen);
    if (EVP_DigestSignFinal(mctx, sig.data(), &siglen) <= 0) {
        throw std::runtime_error("SM2 sign final 失败");
    }
    sig.resize(siglen);
    return bytes_to_hex(sig);
}

bool CryptoUtils::verify_transcript(const std::string& ra_hex, const std::string& id, const std::string& wb_hex,
                                    const std::string& nonce, const std::string& sig_der_hex,
                                    const std::string& full_public_hex) {
    try {
        auto msg = transcript(ra_hex, id, wb_hex, nonce);
        auto pub = hex_to_bytes(full_public_hex);
        if (pub.size() != 65 || pub[0] != 0x04) {
            return false;
        }
        EVP_PKEY* pkey = make_sm2_pkey(pub, nullptr);
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

        auto sig = hex_to_bytes(sig_der_hex);
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
// SM2 解密（DER 密文）
// ---------------------------------------------------------------------------
std::string CryptoUtils::sm2_decrypt(const std::string& ciphertext_der_hex, const std::string& secret_hex) {
    auto der = hex_to_bytes(ciphertext_der_hex);
    BnPtr x(hex_to_bn(secret_hex), BN_free);
    auto pub = pub_bytes_from_priv(group_, ctx_, x.get());
    EVP_PKEY* pkey = make_sm2_pkey(pub, x.get());
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey_guard(pkey, EVP_PKEY_free);

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_pkey(nullptr, pkey, nullptr);
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx_guard(ctx, EVP_PKEY_CTX_free);
    size_t outlen = 0;
    if (!ctx || EVP_PKEY_decrypt_init(ctx) <= 0
        || EVP_PKEY_decrypt(ctx, nullptr, &outlen, der.data(), der.size()) <= 0) {
        throw std::runtime_error("SM2 decrypt 初始化失败");
    }
    std::vector<unsigned char> out(outlen);
    if (EVP_PKEY_decrypt(ctx, out.data(), &outlen, der.data(), der.size()) <= 0) {
        throw std::runtime_error("SM2 decrypt 失败（密文非法或密钥不匹配）");
    }
    out.resize(outlen);
    return bytes_to_hex(out);
}

// ---------------------------------------------------------------------------
// 会话密钥（SM3）
// ---------------------------------------------------------------------------
std::string CryptoUtils::derive_session_key(const std::string& eph_secret_hex, const std::string& peer_point_hex,
                                            const std::string& ra_hex, const std::string& rb_hex,
                                            const std::string& ida, const std::string& idb,
                                            const std::string& nonce) {
    BnPtr scalar(hex_to_bn(eph_secret_hex), BN_free);
    PointPtr peer(point_from_hex(peer_point_hex), EC_POINT_free);
    PointPtr shared(EC_POINT_new(group_), EC_POINT_free);
    EC_POINT_mul(group_, shared.get(), nullptr, peer.get(), scalar.get(), ctx_);
    BnPtr px(BN_new(), BN_free);
    BnPtr py(BN_new(), BN_free);
    EC_POINT_get_affine_coordinates(group_, shared.get(), px.get(), py.get(), ctx_);
    std::vector<unsigned char> input(32);
    BN_bn2binpad(px.get(), input.data(), 32);
    auto append_hex = [&](const std::string& hex) {
        auto bytes = hex_to_bytes(hex);
        input.insert(input.end(), bytes.begin(), bytes.end());
    };
    append_hex(ra_hex);
    append_hex(rb_hex);
    input.insert(input.end(), ida.begin(), ida.end());
    input.insert(input.end(), idb.begin(), idb.end());
    input.insert(input.end(), nonce.begin(), nonce.end());
    return bytes_to_hex(sm3(input));
}

std::string CryptoUtils::hmac_sm3_hex(const std::string& key_hex, const std::string& data_hex) {
    auto key = hex_to_bytes(key_hex);
    auto data = hex_to_bytes(data_hex);
    unsigned int len = 0;
    std::vector<unsigned char> out(EVP_MAX_MD_SIZE);
    HMAC(EVP_sm3(), key.data(), static_cast<int>(key.size()),
         data.data(), data.size(), out.data(), &len);
    out.resize(len);
    return bytes_to_hex(out);
}

std::string CryptoUtils::sm3_hex_of_ascii(const std::string& ascii) const {
    std::vector<unsigned char> bytes(ascii.begin(), ascii.end());
    return bytes_to_hex(sm3(bytes));
}

// ---------------------------- 辅助函数 ----------------------------

std::string CryptoUtils::bn_to_fixed_hex(const BIGNUM* bn) const {
    char* hex = BN_bn2hex(bn);
    std::string s(hex);
    OPENSSL_free(hex);
    for (auto& c : s) {
        if (c >= 'A' && c <= 'F') { c = static_cast<char>(c - 'A' + 'a'); }
    }
    if (s.size() < 64) {
        s.insert(0, 64 - s.size(), '0');
    }
    return s;
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

std::vector<unsigned char> CryptoUtils::transcript(const std::string& ra_hex, const std::string& id,
                                                   const std::string& wb_hex, const std::string& nonce) const {
    auto ra = hex_to_bytes(ra_hex);
    auto wb = hex_to_bytes(wb_hex);
    std::vector<unsigned char> out;
    auto append_len = [&](std::size_t len) {
        out.push_back(static_cast<unsigned char>((len >> 8) & 0xff));
        out.push_back(static_cast<unsigned char>(len & 0xff));
    };
    append_len(ra.size());
    out.insert(out.end(), ra.begin(), ra.end());
    append_len(id.size());
    out.insert(out.end(), id.begin(), id.end());
    append_len(wb.size());
    out.insert(out.end(), wb.begin(), wb.end());
    append_len(nonce.size());
    out.insert(out.end(), nonce.begin(), nonce.end());
    return out;
}

std::vector<unsigned char> CryptoUtils::point_to_bytes(const EC_POINT* point) const {
    std::vector<unsigned char> out(65);
    size_t len = EC_POINT_point2oct(group_, point, POINT_CONVERSION_UNCOMPRESSED, out.data(), out.size(), ctx_);
    out.resize(len);
    return out;
}

EC_POINT* CryptoUtils::point_from_hex(const std::string& hex) const {
    auto bytes = hex_to_bytes(hex);
    if (bytes.size() != 65 || bytes[0] != 0x04) {
        throw std::runtime_error("非法 SEC1 非压缩点");
    }
    EC_POINT* point = EC_POINT_new(group_);
    if (!EC_POINT_oct2point(group_, point, bytes.data(), bytes.size(), ctx_)
        || EC_POINT_is_on_curve(group_, point, ctx_) != 1) {
        EC_POINT_free(point);
        throw std::runtime_error("点不在曲线上");
    }
    return point;
}

BIGNUM* CryptoUtils::random_scalar() const {
    BIGNUM* out = BN_new();
    do {
        BN_rand_range(out, order_);
    } while (BN_is_zero(out));
    return out;
}
