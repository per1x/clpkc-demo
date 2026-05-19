#include "crypto_utils.h"

#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdexcept>

namespace {
using BnPtr = std::unique_ptr<BIGNUM, decltype(&BN_free)>;
using PointPtr = std::unique_ptr<EC_POINT, decltype(&EC_POINT_free)>;
}

CryptoUtils::CryptoUtils() {
    group_ = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    ctx_ = BN_CTX_new();
    order_ = BN_new();
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
    PointPtr Y_i(EC_POINT_new(group_), EC_POINT_free);
    EC_POINT_mul(group_, Y_i.get(), d.get(), nullptr, nullptr, ctx_);
    return bytes_to_hex(point_to_bytes(Y_i.get()));
}

std::string CryptoUtils::hash_point_to_scalar(const std::string& point_hex) const {
    auto point_bytes = hex_to_bytes(point_hex);
    std::vector<unsigned char> coords(point_bytes.begin() + 1, point_bytes.end());
    auto digest = sha256(coords);
    BIGNUM* out = BN_bin2bn(digest.data(), static_cast<int>(digest.size()), nullptr);
    BN_mod(out, out, order_, ctx_);
    if (BN_is_zero(out)) { BN_one(out); }
    return bn_to_fixed_hex(out);
}

std::string CryptoUtils::derive_full_public(const std::string& public_hex, const std::string& derived_public_hex) {
    PointPtr p(point_from_hex(public_hex), EC_POINT_free);
    PointPtr y(point_from_hex(derived_public_hex), EC_POINT_free);
    PointPtr full(EC_POINT_new(group_), EC_POINT_free);
    EC_POINT_add(group_, full.get(), p.get(), y.get(), ctx_);
    return bytes_to_hex(point_to_bytes(full.get()));
}

Signature CryptoUtils::sign_transcript(const std::string& ra_hex, const std::string& id, const std::string& wb_hex,
                                       const std::string& t, const std::string& full_private_hex) {
    BnPtr sk(hex_to_bn(full_private_hex), BN_free);
    BnPtr k(random_scalar(), BN_free);
    PointPtr r_point(EC_POINT_new(group_), EC_POINT_free);
    EC_POINT_mul(group_, r_point.get(), k.get(), nullptr, nullptr, ctx_);
    auto r_bytes = point_to_bytes(r_point.get());
    auto tx = transcript(ra_hex, id, wb_hex, t);
    std::vector<unsigned char> input = r_bytes;
    input.insert(input.end(), tx.begin(), tx.end());
    auto digest = sha256(input);
    BnPtr e(BN_bin2bn(digest.data(), static_cast<int>(digest.size()), nullptr), BN_free);
    BN_mod(e.get(), e.get(), order_, ctx_);
    if (BN_is_zero(e.get())) { BN_one(e.get()); }
    BnPtr s(BN_new(), BN_free);
    BN_mod_mul(s.get(), e.get(), sk.get(), order_, ctx_);
    BN_mod_add(s.get(), k.get(), s.get(), order_, ctx_);
    return {bytes_to_hex(r_bytes), bn_to_fixed_hex(s.get())};
}

bool CryptoUtils::verify_transcript(const std::string& ra_hex, const std::string& id, const std::string& wb_hex,
                                    const std::string& t, const std::string& sig_hex, const std::string& full_public_hex) {
    const std::string r_hex = sig_hex.substr(0, 130);
    const std::string s_hex = sig_hex.substr(130);
    PointPtr r(point_from_hex(r_hex), EC_POINT_free);
    PointPtr pk(point_from_hex(full_public_hex), EC_POINT_free);
    BnPtr s(hex_to_bn(s_hex), BN_free);
    auto tx = transcript(ra_hex, id, wb_hex, t);
    auto r_bytes = hex_to_bytes(r_hex);
    std::vector<unsigned char> input = r_bytes;
    input.insert(input.end(), tx.begin(), tx.end());
    auto digest = sha256(input);
    BnPtr e(BN_bin2bn(digest.data(), static_cast<int>(digest.size()), nullptr), BN_free);
    BN_mod(e.get(), e.get(), order_, ctx_);
    if (BN_is_zero(e.get())) { BN_one(e.get()); }
    PointPtr left(EC_POINT_new(group_), EC_POINT_free);
    PointPtr epk(EC_POINT_new(group_), EC_POINT_free);
    PointPtr right(EC_POINT_new(group_), EC_POINT_free);
    EC_POINT_mul(group_, left.get(), s.get(), nullptr, nullptr, ctx_);
    EC_POINT_mul(group_, epk.get(), nullptr, pk.get(), e.get(), ctx_);
    EC_POINT_add(group_, right.get(), r.get(), epk.get(), ctx_);
    return EC_POINT_cmp(group_, left.get(), right.get(), ctx_) == 0;
}

std::string CryptoUtils::derive_session_key(const std::string& eph_secret_hex, const std::string& peer_point_hex,
                                            const std::string& ra_hex, const std::string& rb_hex,
                                            const std::string& ida, const std::string& idb,
                                            const std::string& ta, const std::string& tb) {
    BnPtr scalar(hex_to_bn(eph_secret_hex), BN_free);
    PointPtr peer(point_from_hex(peer_point_hex), EC_POINT_free);
    PointPtr shared(EC_POINT_new(group_), EC_POINT_free);
    EC_POINT_mul(group_, shared.get(), nullptr, peer.get(), scalar.get(), ctx_);
    BIGNUM* x = BN_new();
    BIGNUM* y = BN_new();
    EC_POINT_get_affine_coordinates(group_, shared.get(), x, y, ctx_);
    std::vector<unsigned char> input = hex_to_bytes(bn_to_fixed_hex(x));
    BN_free(x);
    BN_free(y);
    auto append_hex = [&](const std::string& hex) {
        auto bytes = hex_to_bytes(hex);
        input.insert(input.end(), bytes.begin(), bytes.end());
    };
    append_hex(ra_hex);
    append_hex(rb_hex);
    input.insert(input.end(), ida.begin(), ida.end());
    input.insert(input.end(), idb.begin(), idb.end());
    input.insert(input.end(), ta.begin(), ta.end());
    input.insert(input.end(), tb.begin(), tb.end());
    return bytes_to_hex(sha256(input));
}

std::string CryptoUtils::hmac_sha256_hex(const std::string& key_hex, const std::string& data_hex) {
    auto key = hex_to_bytes(key_hex);
    auto data = hex_to_bytes(data_hex);
    unsigned int len = SHA256_DIGEST_LENGTH;
    std::vector<unsigned char> out(len);
    HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
         data.data(), data.size(), out.data(), &len);
    return bytes_to_hex(out);
}

std::string CryptoUtils::ecies_decrypt(const std::string& ciphertext_hex, const std::string& secret_hex) {
    auto blob = hex_to_bytes(ciphertext_hex);
    if (blob.size() < 65 + 12 + 16) {
        throw std::runtime_error("invalid ECIES ciphertext length");
    }
    auto r_bytes = std::vector<unsigned char>(blob.begin(), blob.begin() + 65);
    auto nonce = std::vector<unsigned char>(blob.begin() + 65, blob.begin() + 77);
    auto ciphertext = std::vector<unsigned char>(blob.begin() + 77, blob.end() - 16);
    auto tag = std::vector<unsigned char>(blob.end() - 16, blob.end());

    PointPtr R(EC_POINT_new(group_), EC_POINT_free);
    EC_POINT_oct2point(group_, R.get(), r_bytes.data(), r_bytes.size(), ctx_);

    BnPtr x(hex_to_bn(secret_hex), BN_free);
    PointPtr S(EC_POINT_new(group_), EC_POINT_free);
    EC_POINT_mul(group_, S.get(), nullptr, R.get(), x.get(), ctx_);

    BIGNUM* sx = BN_new();
    BIGNUM* sy = BN_new();
    EC_POINT_get_affine_coordinates(group_, S.get(), sx, sy, ctx_);
    std::vector<unsigned char> x_coord(32);
    BN_bn2binpad(sx, x_coord.data(), 32);
    BN_free(sx);
    BN_free(sy);

    auto key = sha256(x_coord);

    EVP_CIPHER_CTX* evp_ctx = EVP_CIPHER_CTX_new();
    if (!evp_ctx) {
        throw std::runtime_error("EVP_CIPHER_CTX_new failed");
    }
    int len = 0;
    std::vector<unsigned char> plaintext(ciphertext.size());
    if (!EVP_DecryptInit_ex(evp_ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr)) {
        EVP_CIPHER_CTX_free(evp_ctx);
        throw std::runtime_error("EVP_DecryptInit_ex failed");
    }
    if (!EVP_CIPHER_CTX_ctrl(evp_ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce.size()), nullptr)) {
        EVP_CIPHER_CTX_free(evp_ctx);
        throw std::runtime_error("EVP_CIPHER_CTX_ctrl SET_IVLEN failed");
    }
    if (!EVP_DecryptInit_ex(evp_ctx, nullptr, nullptr, key.data(), nonce.data())) {
        EVP_CIPHER_CTX_free(evp_ctx);
        throw std::runtime_error("EVP_DecryptInit_ex key/nonce failed");
    }
    if (!EVP_DecryptUpdate(evp_ctx, plaintext.data(), &len, ciphertext.data(), static_cast<int>(ciphertext.size()))) {
        EVP_CIPHER_CTX_free(evp_ctx);
        throw std::runtime_error("EVP_DecryptUpdate failed");
    }
    int plaintext_len = len;
    if (!EVP_CIPHER_CTX_ctrl(evp_ctx, EVP_CTRL_GCM_SET_TAG, static_cast<int>(tag.size()), tag.data())) {
        EVP_CIPHER_CTX_free(evp_ctx);
        throw std::runtime_error("EVP_CIPHER_CTX_ctrl SET_TAG failed");
    }
    if (!EVP_DecryptFinal_ex(evp_ctx, plaintext.data() + plaintext_len, &len)) {
        EVP_CIPHER_CTX_free(evp_ctx);
        throw std::runtime_error("EVP_DecryptFinal_ex failed: tag verification failed");
    }
    plaintext_len += len;
    EVP_CIPHER_CTX_free(evp_ctx);
    plaintext.resize(plaintext_len);
    return bytes_to_hex(plaintext);
}

std::string CryptoUtils::bn_to_fixed_hex(const BIGNUM* bn) const {
    char* hex = BN_bn2hex(bn);
    std::string s(hex);
    OPENSSL_free(hex);
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

std::vector<unsigned char> CryptoUtils::sha256(const std::vector<unsigned char>& data) const {
    std::vector<unsigned char> out(SHA256_DIGEST_LENGTH);
    SHA256(data.data(), data.size(), out.data());
    return out;
}

std::vector<unsigned char> CryptoUtils::transcript(const std::string& ra_hex, const std::string& id,
                                                   const std::string& wb_hex, const std::string& t) const {
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
    append_len(t.size());
    out.insert(out.end(), t.begin(), t.end());
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
    EC_POINT* point = EC_POINT_new(group_);
    EC_POINT_oct2point(group_, point, bytes.data(), bytes.size(), ctx_);
    return point;
}

BIGNUM* CryptoUtils::random_scalar() const {
    BIGNUM* out = BN_new();
    do {
        BN_rand_range(out, order_);
    } while (BN_is_zero(out));
    return out;
}