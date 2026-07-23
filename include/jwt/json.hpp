#pragma once

#include <string>
#include <string_view>
#include <cctype>

#include "types.hpp"

namespace jwt::detail {

inline Claims parse_json_object(std::string_view json) {
    Claims claims;

    auto start = json.find('{');
    auto end   = json.rfind('}');
    if (start == std::string_view::npos || end == std::string_view::npos)
        throw MalformedError("Invalid JSON object");

    std::string body(json.substr(start + 1, end - start - 1));
    size_t i = 0;

    auto skip_ws = [&]() {
        while (i < body.size() && std::isspace(static_cast<unsigned char>(body[i])))
            ++i;
    };

    auto read_string = [&]() -> std::string {
        if (body[i] != '"') throw MalformedError("Expected '\"' in JSON");
        ++i;
        std::string s;
        while (i < body.size() && body[i] != '"') {
            if (body[i] == '\\' && i + 1 < body.size()) {
                ++i;
                switch (body[i]) {
                    case '"':  s += '"';  break;
                    case '\\': s += '\\'; break;
                    case '/':  s += '/';  break;
                    case 'n':  s += '\n'; break;
                    case 'r':  s += '\r'; break;
                    case 't':  s += '\t'; break;
                    default:   s += body[i]; break;
                }
            } else {
                s += body[i];
            }
            ++i;
        }
        if (i < body.size()) ++i; 
        return s;
    };

    while (i < body.size()) {
        skip_ws();
        if (i >= body.size() || body[i] == '}') break;
        if (body[i] == ',') { ++i; continue; }

        std::string key = read_string();
        skip_ws();
        if (i >= body.size() || body[i] != ':')
            throw MalformedError("Expected ':' in JSON");
        ++i;
        skip_ws();

        JsonValue val;

        if (body[i] == '"') {
            val.type = JsonValue::Type::String;
            val.str  = read_string();

        } else if (body.substr(i, 4) == "true") {
            val.type = JsonValue::Type::Bool;
            val.flag = true;
            i += 4;

        } else if (body.substr(i, 5) == "false") {
            val.type = JsonValue::Type::Bool;
            val.flag = false;
            i += 5;

        } else if (body.substr(i, 4) == "null") {
            val.type = JsonValue::Type::Null;
            i += 4;

        } else if (body[i] == '[' || body[i] == '{') {
            char open  = body[i];
            char close = (open == '[') ? ']' : '}';
            int  depth = 1;
            ++i;
            size_t vs = i;
            while (i < body.size() && depth > 0) {
                if (body[i] == open)  ++depth;
                if (body[i] == close) --depth;
                ++i;
            }
            val.type = JsonValue::Type::String;
            val.str  = body.substr(vs - 1, i - vs + 1);

        } else {
            size_t ns = i;
            if (body[i] == '-') ++i;
            while (i < body.size() &&
                   (std::isdigit(static_cast<unsigned char>(body[i])) ||
                    body[i] == '.' || body[i] == 'e' || body[i] == 'E' ||
                    body[i] == '+' || body[i] == '-'))
                ++i;
            val.type = JsonValue::Type::Number;
            val.num  = std::stod(body.substr(ns, i - ns));
        }

        claims[std::move(key)] = std::move(val);
    }

    return claims;
}

}
