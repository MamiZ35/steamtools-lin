// SteamCore - StableClient (Linux port of api/stable_client.cpp + sub_1800381E0)
// Real SteamTools API signing. Reference (base/source + decompile):
//   POST <base>/api/<cmd>
//   Headers:
//     X-Proto-Version     (ref: word_1801BAB28 = "1")
//     X-Proto-Client      "Core"
//     X-Proto-SteamID     (steamid64)
//     X-Proto-Timestamp   (unix ts)
//     X-Proto-Nonce       (16 hex chars)
//     X-Proto-Compressed  ("0"/"1")  [sub_1800381E0]
//     X-Proto-Sig         (SHA-256 hex of request body)  [base/source stable_client.cpp]
//     Content-Type        application/octet-stream
//     User-Agent          SteamTools/3.0  [base/scripts/download_*.py]
//   Body: raw JSON (per reconstructed reference; base/source does not zlib-compress).
//   Sig: SHA-256 hex of body (mbedTLS SHA-256 in reference; we use OpenSSL EVP).
#include "steamcore.h"
#include <curl/curl.h>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>
#include <chrono>
#include <random>
#include <cstdio>
#include <cstddef>
#include <cstdlib>

namespace steamcore {
namespace api {

namespace {
size_t write_cb(void* ptr, size_t size, size_t nmemb, void* user) {
    auto* v = static_cast<std::vector<uint8_t>*>(user);
    size_t real = size * nmemb;
    v->insert(v->end(), static_cast<uint8_t*>(ptr),
              static_cast<uint8_t*>(ptr) + real);
    return real;
}

std::string hex_bytes(const uint8_t* d, size_t len) {
    static const char* hex = "0123456789abcdef";
    std::string s(len*2, '0');
    for (size_t i = 0; i < len; i++) { s[i*2] = hex[d[i]>>4]; s[i*2+1] = hex[d[i]&0xF]; }
    return s;
}
std::string rand_hex16() {
    uint8_t buf[16]{};
    static std::random_device rd;
    std::mt19937_64 g(rd());
    std::uniform_int_distribution<uint8_t> dist(0,255);
    for (int i = 0; i < 16; i++) buf[i] = dist(g);
    return hex_bytes(buf, 16);
}

}  // namespace (anon)

StableClient::StableClient(std::string host) : host_(std::move(host)) {
    base_headers_["User-Agent"]        = kUserAgent;
    base_headers_["Accept"]            = "*/*";
    base_headers_["X-Proto-Version"]   = "1";
    base_headers_["X-Proto-Client"]    = "Core";
}

// Real API signing per reference (sub_1800381E0 + base/source).
// sig = SHA-256 hex of request body (mbedTLS SHA-256 in reference).
std::vector<uint8_t> StableClient::call(const std::string& cmd,
                                       const std::string& steamid,
                                       const std::vector<uint8_t>& body,
                                       bool* out_cf_challenge) {
    std::string url = host_ + "/api/" + cmd;
    curl_slist* hdr = nullptr;
    auto append = [&](const char* k, const std::string& v) {
        hdr = curl_slist_append(hdr, (std::string(k) + ": " + v).c_str());
    };
    for (const auto& kv : base_headers_) {
        append(kv.first.c_str(), kv.second);
    }
    auto now = std::chrono::system_clock::now();
    std::string ts = std::to_string(std::chrono::system_clock::to_time_t(now));
    append("X-Proto-SteamID", steamid);
    append("X-Proto-Timestamp", ts);
    std::string nonce = rand_hex16();
    append("X-Proto-Nonce", nonce);
    // X-Proto-Compressed: the body in our client is already the (uncompressed)
    // reference format, so the flag mirrors the reference (raw body = 0).
    append("X-Proto-Compressed", "0");
    // Sig: SHA-256 hex of the request body (matches reconstructed reference).
    std::string sig = crypto::sha256_hex(reinterpret_cast<const uint8_t*>(body.data()), body.size());
    append("X-Proto-Sig", sig);
    append("Content-Type", "application/octet-stream");
    append("X-Requested-With", "");
    // Cloudflare is in front of the real API.  The user (or a browser-based
    // one-off solve) can hand us a valid CF cookie via env to get a real reply
    // instead of the JS-challenge page.
    if (const char* cc = std::getenv("STEAMTOOLS_CF_COOKIE")) {
        if (std::string(cc).size() > 0)
            append("Cookie", std::string(cc));
    }

    std::vector<uint8_t> resp;
    CURL* c = curl_easy_init();
    if (!c) throw std::runtime_error("curl init");
    curl_easy_setopt(c, CURLOPT_URL, url.c_str());
    curl_easy_setopt(c, CURLOPT_HTTPHEADER, hdr);
    curl_easy_setopt(c, CURLOPT_POST, 1L);
    curl_easy_setopt(c, CURLOPT_POSTFIELDSIZE, static_cast<long>(body.size()));
    if (!body.empty()) curl_easy_setopt(c, CURLOPT_POSTFIELDS, body.data());
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, &resp);
    curl_easy_setopt(c, CURLOPT_TIMEOUT, 60L);
    curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 1L);
    // Use a client stack closer to the original (mbedTLS / libcurl 7.74).
    curl_easy_setopt(c, CURLOPT_USERAGENT, kUserAgent);
    CURLcode r = curl_easy_perform(c);
    curl_slist_free_all(hdr);
    curl_easy_cleanup(c);
    if (r != CURLE_OK) throw std::runtime_error(std::string("curl: ") + curl_easy_strerror(r));
    if (out_cf_challenge) {
        std::string content(resp.begin(), resp.end());
        *out_cf_challenge = (content.size() > 200 &&
            content.find("Attention Required") != std::string::npos) ||
            (content.find("__CF$cv$params") != std::string::npos);
    }
    return resp;
}

// Wrapper matching the public api::call(cmd, body) used by eticket.
std::vector<uint8_t> call(const std::string& cmd,
                          const std::vector<uint8_t>& body) {
    static StableClient client(SteamClientApi::base());
    std::string sid = steamcore::get_current_steamid();
    return client.call(cmd, sid, body);
}

}  // namespace api
}  // namespace steamcore
