#pragma once

#include <string>
#include <string_view>
#include <vector>

#include <openssl/bio.h>
#include <openssl/evp.h>

#include "types.hpp"

namespace jwt::detail {

inline std::string base64url_encode(const unsigned char* data, size_t len) {
    static const char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    std::string out;
    out.reserve(((len + 2) / 3) * 4);

    for (size_t i = 0; i < len; i += 3) {
        unsigned int b = static_cast<unsigned char>(data[i]) << 16;
        if (i + 1 < len) b |= static_cast<unsigned char>(data[i + 1]) << 8;
        if (i + 2 < len) b |= static_cast<unsigned char>(data[i + 2]);

        out.push_back(alphabet[(b >> 18) & 0x3F]);
        out.push_back(alphabet[(b >> 12) & 0x3F]);
        if (i + 1 < len) out.push_back(alphabet[(b >> 6) & 0x3F]);
        if (i + 2 < len) out.push_back(alphabet[b & 0x3F]);
    }
    return out;
}

inline std::string base64url_encode(std::string_view sv) {
    return base64url_encode(
        reinterpret_cast<const unsigned char*>(sv.data()), sv.size());
}

inline std::vector<unsigned char> base64url_decode(std::string_view input) {
    std::string b64(input);
    for (char& c : b64) {
        if (c == '-') c = '+';
        else if (c == '_') c = '/';
    }
    while (b64.size() % 4 != 0) b64 += '=';

    std::vector<unsigned char> out(b64.size());

    BIO* mem  = BIO_new_mem_buf(b64.data(), static_cast<int>(b64.size()));
    BIO* b64f = BIO_new(BIO_f_base64());
    BIO_set_flags(b64f, BIO_FLAGS_BASE64_NO_NL);
    mem = BIO_push(b64f, mem);

    int n = BIO_read(mem, out.data(), static_cast<int>(out.size()));
    BIO_free_all(mem);

    if (n < 0)
        throw MalformedError("base64url decode failed");

    out.resize(static_cast<size_t>(n));
    return out;
}

}
