#pragma once

#include <string_view>
#include <vector>

#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>

#include "types.hpp"

namespace jwt::detail {

inline bool verify_hs256(std::string_view        signing_input,
                          std::string_view        secret,
                          const std::vector<unsigned char>& sig) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int  digest_len = 0;

    HMAC(EVP_sha256(),
         secret.data(),       static_cast<int>(secret.size()),
         reinterpret_cast<const unsigned char*>(signing_input.data()),
         signing_input.size(),
         digest, &digest_len);

    if (digest_len != sig.size()) return false;

    unsigned char diff = 0;
    for (size_t i = 0; i < digest_len; ++i)
        diff |= digest[i] ^ sig[i];
    return diff == 0;
}

inline bool verify_rs256(std::string_view        signing_input,
                          std::string_view        public_key_pem,
                          const std::vector<unsigned char>& sig) {
    BIO* bio = BIO_new_mem_buf(public_key_pem.data(),
                               static_cast<int>(public_key_pem.size()));
    if (!bio) return false;

    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!pkey) return false;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    bool ok = false;

    if (ctx) {
        if (EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, pkey) == 1) {
            EVP_DigestVerifyUpdate(ctx, signing_input.data(), signing_input.size());
            ok = (EVP_DigestVerifyFinal(ctx, sig.data(), sig.size()) == 1);
        }
        EVP_MD_CTX_free(ctx);
    }

    EVP_PKEY_free(pkey);
    return ok;
}

inline std::vector<unsigned char> hmac_sha256(std::string_view data,
                                               std::string_view key) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int  digest_len = 0;

    HMAC(EVP_sha256(),
         key.data(),  static_cast<int>(key.size()),
         reinterpret_cast<const unsigned char*>(data.data()),
         data.size(),
         digest, &digest_len);

    return std::vector<unsigned char>(digest, digest + digest_len);
}

}
