#pragma once

#include <string>
#include <string_view>
#include <unordered_map>

#include "types.hpp"
#include "base64.hpp"
#include "crypto.hpp"

namespace jwt {

inline std::string encode_hs256(
    const std::unordered_map<std::string, std::string>& claims,
    std::string_view secret)
{
    const std::string header_json  = R"({"alg":"HS256","typ":"JWT"})";
    const std::string enc_header   = detail::base64url_encode(header_json);

    // Payload — build minimal JSON
    std::string payload_json = "{";
    bool first = true;
    for (auto& [k, v] : claims) {
        if (!first) payload_json += ',';
        first = false;
        payload_json += '"';
        payload_json += k;
        payload_json += "\":";
        if (!v.empty() && v[0] == '~') {
            payload_json += v.substr(1);
        } else {
            payload_json += '"';
            payload_json += v;
            payload_json += '"';
        }
    }
    payload_json += '}';
    const std::string enc_payload = detail::base64url_encode(payload_json);

    const std::string signing_input = enc_header + "." + enc_payload;

    auto sig_bytes = detail::hmac_sha256(signing_input, secret);
    const std::string enc_sig = detail::base64url_encode(
        sig_bytes.data(), sig_bytes.size());

    return signing_input + "." + enc_sig;
}

inline std::string encode_hs384(
    const std::unordered_map<std::string, std::string>& claims,
    std::string_view secret)
{
    const std::string header_json = R"({"alg":"HS384","typ":"JWT"})";
    const std::string enc_header  = detail::base64url_encode(header_json);

    std::string payload_json = "{";
    bool first = true;
    for (auto& [k, v] : claims) {
        if (!first) payload_json += ',';
        first = false;
        payload_json += '"';
        payload_json += k;
        payload_json += "\":";
        if (!v.empty() && v[0] == '~') {
            payload_json += v.substr(1);
        } else {
            payload_json += '"';
            payload_json += v;
            payload_json += '"';
        }
    }
    payload_json += '}';
    const std::string enc_payload = detail::base64url_encode(payload_json);

    const std::string signing_input = enc_header + "." + enc_payload;

    auto sig_bytes = detail::hmac_sha384(signing_input, secret);
    const std::string enc_sig = detail::base64url_encode(
        sig_bytes.data(), sig_bytes.size());

    return signing_input + "." + enc_sig;
}

} // namespace jwt
