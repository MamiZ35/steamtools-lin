// crypto test: verify identical keys produce identical decrypt output
#include "steamcore.h"
#include <cstdio>
#include <iostream>
#include <string>
#include <vector>

int main() {
    std::string sample = "SteamTools Linux port - AES-256-CBC + zlib round-trip test string";
    std::vector<uint8_t> enc = steamcore::aes256cbc_zlib_encrypt(
        std::vector<uint8_t>(sample.begin(), sample.end()), steamcore::kCoreKey);
    std::vector<uint8_t> dec = steamcore::aes256cbc_zlib_decrypt(enc, steamcore::kCoreKey);
    bool ok = (dec == std::vector<uint8_t>(sample.begin(), sample.end()));
    std::cout << "[Crypto] AES-256-CBC + zlib round-trip: "
              << (ok ? "PASS" : "FAIL") << std::endl;
    std::cout << "[Crypto] kVersionKey: " << steamcore::kVersionKey.size() << " bytes" << std::endl;
    std::cout << "[Crypto] kCoreKey:    " << steamcore::kCoreKey.size() << " bytes" << std::endl;
    uint8_t buf[] = {1, 2, 3, 4, 5};
    std::string b64 = steamcore::crypto::base64_encode(buf, sizeof(buf));
    std::cout << "[Crypto] base64 test: " << b64 << std::endl;
    // SHA-1 (used by BetaClient envelope) — verify known vector:
    //   sha1("") == da39a3ee5e6b4b0d3255bfef95601890afd80709
    uint8_t sha1_out[20]{};
    steamcore::crypto::sha1(nullptr, 0, sha1_out);
    std::string sha1_test = steamcore::crypto::sha1_hex(nullptr, 0);
    bool sha1_ok = (sha1_test == "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    std::cout << "[Crypto] SHA-1 (empty) hex: " << sha1_test
              << " " << (sha1_ok ? "PASS" : "FAIL") << std::endl;
    std::string mid = steamcore::machine_id();
    std::cout << "[Crypto] machine_id: " << mid << " (length " << mid.size() << ")" << std::endl;
    bool all_ok = ok && sha1_ok;
    return all_ok ? 0 : 1;
}
