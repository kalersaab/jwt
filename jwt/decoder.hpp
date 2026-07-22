#pragma once

#include <string_view>
#include <vector>

#include "types.hpp"
#include "base64.hpp"
#include "json.hpp"
#include "crypto.hpp"

namespace jwt {

inline DecodedToken decode(std::string_view token,
                            std::string_view secret,
                            bool             verify_exp = true)
{

    std::vector<std::string_view> parts;
    {
        size_t start = 0;
        while (true) {
            auto pos = token.find('.', start);
            if (pos == std::string_view::npos) {
                parts.push_back(token.substr(start));
                break;
            }
            parts.push_back(token.substr(start, pos - start));
            start = pos + 1;
        }
    }

    if (parts.size() != 3)
        throw MalformedError(
            "JWT must have exactly 3 parts (header.payload.signature)");

    const auto& enc_header    = parts[0];
    const auto& enc_payload   = parts[1];
    const auto& enc_signature = parts[2];

    auto to_string = [](const std::vector<unsigned char>& v) {
        return std::string(v.begin(), v.end());
    };

    const std::string header_json  = to_string(detail::base64url_decode(enc_header));
    const std::string payload_json = to_string(detail::base64url_decode(enc_payload));
    const auto        sig_bytes    = detail::base64url_decode(enc_signature);

    auto header_claims  = detail::parse_json_object(header_json);
    auto payload_claims = detail::parse_json_object(payload_json);

    DecodedToken result;

    auto require = [&](const std::string& key) -> const JsonValue& {
        auto it = header_claims.find(key);
        if (it == header_claims.end())
            throw MalformedError("Missing '" + key + "' in JWT header");
        return it->second;
    };

    result.alg = require("alg").str;

    if (auto it = header_claims.find("typ"); it != header_claims.end())
        result.typ = it->second.str;
    if (auto it = header_claims.find("kid"); it != header_claims.end())
        result.kid = it->second.str;

    result.payload = std::move(payload_claims);

    const std::string signing_input =
        std::string(enc_header) + "." + std::string(enc_payload);

    if (result.alg == "HS256") {
        if (!detail::verify_hs256(signing_input, secret, sig_bytes))
            throw SignatureError("HS256 signature verification failed");

    } else if (result.alg == "RS256") {
        if (!detail::verify_rs256(signing_input, secret, sig_bytes))
            throw SignatureError("RS256 signature verification failed");

    } else {
        throw AlgorithmError("Unsupported algorithm: " + result.alg);
    }

    if (verify_exp && result.is_expired())
        throw ExpiredError("Token has expired (exp claim)");

    return result;
}

}
