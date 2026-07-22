# jwt.hpp

A lightweight, header-only C++20 JWT decoder and encoder library. No external JSON dependencies — just OpenSSL.

Tokens produced by this library can be verified on [jwt.io](https://jwt.io), and tokens from jwt.io can be decoded and verified here.

---

## Features

- **HS256** — HMAC-SHA256 signing and verification
- **RS256** — RSA-SHA256 signature verification (PEM public key)
- **Decode** any JWT and access claims by key
- **Expiry check** — automatic `exp` claim validation
- **Typed errors** — distinct exception types for each failure mode
- Header-only — drop the `jwt/` folder and `jwt.hpp` into your project and go

---

## Project Structure

```
jwt/
├── jwt/
│   ├── types.hpp    — JsonValue, Claims, DecodedToken, error types
│   ├── base64.hpp   — base64url encode / decode
│   ├── json.hpp     — minimal flat JSON object parser
│   ├── crypto.hpp   — HMAC-SHA256 and RSA-SHA256 verification
│   ├── encoder.hpp  — jwt::encode_hs256()
│   └── decoder.hpp  — jwt::decode()
├── jwt.hpp          — single umbrella include
└── main.cpp         — usage example
```

---

## Requirements

- C++20 or later
- OpenSSL (libssl + libcrypto)

Install OpenSSL on Ubuntu/Debian:

```bash
sudo apt install libssl-dev
```

---

## Building

```bash
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make
```

Or compile directly:

```bash
c++ main.cpp -o jwt -std=c++20 -lssl -lcrypto
```

---

## Usage

### Encode a HS256 token

```cpp
#include "jwt.hpp"

std::unordered_map<std::string, std::string> claims = {
    {"sub",  "1234567890"},
    {"name", "John Doe"},
    {"iat",  "~1516239022"},  // '~' prefix emits a JSON number, not a string
};

std::string token = jwt::encode_hs256(claims, "your-secret");
```

> Prefix numeric/boolean values with `~` so they are emitted as raw JSON values rather than quoted strings — this keeps the token fully compatible with jwt.io.

---

### Decode and verify a token

```cpp
#include "jwt.hpp"

try {
    auto decoded = jwt::decode(token, "your-secret");

    std::cout << decoded.subject()  << "\n";  // sub
    std::cout << decoded.issuer()   << "\n";  // iss
    std::cout << decoded.alg        << "\n";  // HS256

    // Access any claim
    std::cout << decoded.payload["name"].to_string() << "\n";

} catch (const jwt::SignatureError& e) {
    std::cerr << "Bad signature: " << e.what() << "\n";
} catch (const jwt::ExpiredError& e) {
    std::cerr << "Token expired: " << e.what() << "\n";
} catch (const jwt::JwtError& e) {
    std::cerr << "JWT error: " << e.what() << "\n";
}
```

---

### Verify a RS256 token

Pass a PEM-encoded public key as the `secret` parameter:

```cpp
std::string pem = R"(-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOC...
-----END PUBLIC KEY-----)";

auto decoded = jwt::decode(token, pem);
```

---

### Skip expiry check

```cpp
auto decoded = jwt::decode(token, secret, /*verify_exp=*/false);
```

---

## Error Types

| Exception | Thrown when |
|---|---|
| `jwt::MalformedError` | Token structure or encoding is invalid |
| `jwt::AlgorithmError` | `alg` header is missing or unsupported |
| `jwt::SignatureError` | Signature does not match |
| `jwt::ExpiredError` | `exp` claim is in the past |

All derive from `jwt::JwtError` → `std::runtime_error`.

---

## DecodedToken Fields

```cpp
struct DecodedToken {
    std::string alg;     // Algorithm — "HS256" or "RS256"
    std::string typ;     // Type — "JWT"
    std::string kid;     // Key ID (if present)
    Claims      payload; // All claims as a map

    std::string subject();   // payload["sub"]
    std::string issuer();    // payload["iss"]
    std::string audience();  // payload["aud"]
    bool        is_expired();
};
```

---

## License

MIT
