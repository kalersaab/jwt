#pragma once

#include <string>
#include <unordered_map>
#include <stdexcept>
#include <sstream>
#include <chrono>
#include <ctime>

namespace jwt {

struct JsonValue {
    enum class Type { String, Number, Bool, Null };

    Type        type = Type::Null;
    std::string str;
    double      num  = 0;
    bool        flag = false;

    std::string as_string() const { return str; }
    double      as_number() const { return num; }
    bool        as_bool()   const { return flag; }

    std::string to_string() const {
        switch (type) {
            case Type::String: return str;
            case Type::Number: {
                std::ostringstream oss;
                if (num == static_cast<long long>(num))
                    oss << static_cast<long long>(num);
                else
                    oss << num;
                return oss.str();
            }
            case Type::Bool: return flag ? "true" : "false";
            case Type::Null: return "null";
        }
        return "null";
    }
};

using Claims = std::unordered_map<std::string, JsonValue>;

struct DecodedToken {
    std::string alg;
    std::string typ;
    std::string kid;  
    Claims      payload;

    std::string subject()  const { return get_string("sub"); }
    std::string issuer()   const { return get_string("iss"); }
    std::string audience() const { return get_string("aud"); }

    bool is_expired() const {
        auto it = payload.find("exp");
        if (it == payload.end() || it->second.type != JsonValue::Type::Number)
            return false;
        auto exp = static_cast<std::time_t>(it->second.num);
        auto now = std::chrono::system_clock::to_time_t(
            std::chrono::system_clock::now());
        return now > exp;
    }

private:
    std::string get_string(const std::string& key) const {
        auto it = payload.find(key);
        if (it == payload.end()) return {};
        return it->second.to_string();
    }
};

struct JwtError       : std::runtime_error { using std::runtime_error::runtime_error; };
struct SignatureError : JwtError           { using JwtError::JwtError; };
struct MalformedError : JwtError           { using JwtError::JwtError; };
struct AlgorithmError : JwtError           { using JwtError::JwtError; };
struct ExpiredError   : JwtError           { using JwtError::JwtError; };

}
