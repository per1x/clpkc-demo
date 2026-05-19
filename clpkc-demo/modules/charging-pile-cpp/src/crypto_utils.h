#pragma once

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <map>
#include <memory>
#include <string>
#include <vector>

struct KeyMaterial {
    std::string secret_hex;
    std::string public_hex;
};

struct Signature {
    std::string r_hex;
    std::string s_hex;

    std::string to_hex() const {
        return r_hex + s_hex;
    }
};

class CryptoUtils {
public:
    CryptoUtils();
    ~CryptoUtils();

    KeyMaterial generate_static_key();
    std::string compose_full_private(const std::string& secret_hex, const std::string& partial_hex);
    std::string compute_derived_public(const std::string& point_hex);
    std::string derive_full_public(const std::string& public_hex, const std::string& derived_public_hex);
    Signature sign_transcript(const std::string& ra_hex, const std::string& id, const std::string& wb_hex,
                              const std::string& t, const std::string& full_private_hex);
    bool verify_transcript(const std::string& ra_hex, const std::string& id, const std::string& wb_hex,
                           const std::string& t, const std::string& sig_hex, const std::string& full_public_hex);
    std::string derive_session_key(const std::string& eph_secret_hex, const std::string& peer_point_hex,
                                   const std::string& ra_hex, const std::string& rb_hex,
                                   const std::string& ida, const std::string& idb,
                                   const std::string& ta, const std::string& tb);
    std::string hmac_sha256_hex(const std::string& key_hex, const std::string& data_hex);
    std::string ecies_decrypt(const std::string& encrypted_blob_hex, const std::string& private_key_hex);

private:
    EC_GROUP* group_;
    BN_CTX* ctx_;
    BIGNUM* order_;

    std::string bn_to_fixed_hex(const BIGNUM* bn) const;
    BIGNUM* hex_to_bn(const std::string& hex) const;
    std::vector<unsigned char> hex_to_bytes(const std::string& hex) const;
    std::string bytes_to_hex(const std::vector<unsigned char>& data) const;
    std::vector<unsigned char> sha256(const std::vector<unsigned char>& data) const;
    std::vector<unsigned char> transcript(const std::string& ra_hex, const std::string& id,
                                          const std::string& wb_hex, const std::string& t) const;
    std::string hash_point_to_scalar(const std::string& point_hex) const;
    std::vector<unsigned char> point_to_bytes(const EC_POINT* point) const;
    EC_POINT* point_from_hex(const std::string& hex) const;
    BIGNUM* random_scalar() const;
};