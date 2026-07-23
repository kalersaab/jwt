#include <iostream>
#include "include/jwt.hpp"

int main() {

    const std::string secret = "your-256-bit-secret";

    std::unordered_map<std::string, std::string> claims = {
        {"sub",  "1234567890"},
        {"name", "john Doe"},
        {"iat",  "~1516239022"},
    };

    std::string token = jwt::encode_hs256(claims, secret);
    std::cout << "=== Encoded JWT ===\n" << token << "\n\n";

    try {
        auto decoded = jwt::decode(token, secret, false);

        std::cout << "=== Decoded JWT ===\n";
        std::cout << "Algorithm : " << decoded.alg << "\n";
        std::cout << "Type      : " << decoded.typ << "\n";
        std::cout << "Subject   : " << decoded.subject() << "\n";

        std::cout << "\n--- All claims ---\n";
        for (auto& [key, val] : decoded.payload)
            std::cout << "  " << key << " = " << val.to_string() << "\n";

    } catch (const jwt::SignatureError& e) {
        std::cerr << "Signature error: " << e.what() << "\n";
    } catch (const jwt::ExpiredError& e) {
        std::cerr << "Token expired: " << e.what() << "\n";
    } catch (const jwt::JwtError& e) {
        std::cerr << "JWT error: " << e.what() << "\n";
    }

    std::cout << "\n=== Tampered secret (should fail) ===\n";
    try {
        jwt::decode(token, "wrong-secret", false);
        std::cout << "Verification passed (unexpected)\n";
    } catch (const jwt::SignatureError& e) {
        std::cout << "Caught expected error: " << e.what() << "\n";
    }

    std::cout << "\n=== HS384 Encoded JWT ===\n";
    std::string token384 = jwt::encode_hs384(claims, secret);
    std::cout << token384 << "\n\n";

    try {
        auto decoded384 = jwt::decode(token384, secret, false);

        std::cout << "=== HS384 Decoded JWT ===\n";
        std::cout << "Algorithm : " << decoded384.alg << "\n";
        std::cout << "Subject   : " << decoded384.subject() << "\n";

        std::cout << "\n--- All claims ---\n";
        for (auto& [key, val] : decoded384.payload)
            std::cout << "  " << key << " = " << val.to_string() << "\n";

    } catch (const jwt::JwtError& e) {
        std::cerr << "JWT error: " << e.what() << "\n";
    }

    return 0;
}
