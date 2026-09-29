// SteamCore - beta channel client (Linux port of base/source/CoreBeta)
// Mirrors sub_18003FC80 (JSON client), sub_18003FBA0 (host + "/api"),
// sub_1800137F0 (auto host selection) from CoreBeta_decrypted.bin.
//
// Protocol (SHA-1, NOT SHA-256 like Stable):
//   env = { "time": <unix_ts>, "sKey": <sha1_hex(data)>, "data": <hex(data)> }
//   POST <host>/api/<cmd>  (Content-Type: application/json)
// Host auto-selected: POST <host>/api/test to each candidate; first returning "1" wins.
#include "steamcore.h"
#include <curl/curl.h>
#include <chrono>
#include <ctime>
#include <stdexcept>
#include <string>
#include <vector>

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

std::vector<uint8_t> http_post(const std::string& url,
                               const std::vector<uint8_t>& body,
                               const std::string& ua,
                               const std::string& cookie) {
    std::vector<uint8_t> resp;
    CURL* c = curl_easy_init();
    if (!c) throw std::runtime_error("curl init");
    curl_easy_setopt(c, CURLOPT_URL, url.c_str());
    curl_easy_setopt(c, CURLOPT_POST, 1L);
    if (!body.empty()) {
        curl_easy_setopt(c, CURLOPT_POSTFIELDSIZE, static_cast<long>(body.size()));
        curl_easy_setopt(c, CURLOPT_POSTFIELDS, body.data());
    }
    // Mirrors stable_client: a User-Agent and an optional Cloudflare cookie are
    // required to get through the JS-challenge in front of the live API.
    if (!ua.empty()) curl_easy_setopt(c, CURLOPT_USERAGENT, ua.c_str());
    if (!cookie.empty()) curl_easy_setopt(c, CURLOPT_COOKIE, cookie.c_str());
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, &resp);
    curl_easy_setopt(c, CURLOPT_TIMEOUT, 30L);
    CURLcode r = curl_easy_perform(c);
    curl_easy_cleanup(c);
    if (r != CURLE_OK) throw std::runtime_error(std::string("curl: ") + curl_easy_strerror(r));
    return resp;
}

}  // namespace anon

const std::vector<std::string>& BetaClient::candidate_hosts() {
    // Host DISCOVERY now comes from the manifest "urls" field (host_cfg),
    // shared with the stable client.  The original build (sub_18003FC80)
    // derives BetaClient::autoselect from sub_18003FBA0, which itself reads
    // a global host string written by sub_1800137F0 (autoselect from the
    // manifest's "urls" list).  The recovered hardcoded list below is preserved
    // as the OFFLINE fallback so the client still works if the manifest is not
    // fetched / the "urls" array is empty.
    // Host SELECTION (autoselect) is unchanged: probe each candidate with
    // POST <host>/api/test and keep the first that returns '1'.
    static std::vector<std::string> hosts;
    static bool loaded = false;
    if (loaded) return hosts;
    loaded = true;
    hosts = api_hosts();   // manifest "urls" (authoritative) or recovered fallback
    return hosts;
}

BetaClient::BetaClient(std::string host) : host_(std::move(host)) {}

static std::string cf_cookie() {
    const char* c = std::getenv("STEAMTOOLS_CF_COOKIE");
    return c ? std::string(c) : std::string();
}

BetaClient BetaClient::autoselect() {
    static const char* ua = steamcore::api::kUserAgent;
    std::string cookie = cf_cookie();
    for (const auto& h : candidate_hosts()) {
        try {
            auto r = http_post(h + "/api/test", {}, ua, cookie);
            if (!r.empty() && r[0] == '1') return BetaClient(h);
        } catch (...) {
            (void)0;
        }
    }
    throw std::runtime_error("no Beta host answered /api/test");
}

// Builds envelope {time, sKey, data} exactly as sub_18003FC80.
// sKey = SHA-1 hex of `data`, data = raw hex of `data`.
// Posts to <host>/api/<cmd>.
std::vector<uint8_t> BetaClient::call(const std::string& cmd,
                                     const std::vector<uint8_t>& data) {
    auto now = std::chrono::system_clock::now();
    std::string time = std::to_string(std::chrono::system_clock::to_time_t(now));
    std::string skey = steamcore::crypto::sha1_hex(data.data(), data.size());
    std::string env = "{\"time\":" + time + ",\"sKey\":\"" + skey + "\",\"data\":\"";
    static const char* hx = "0123456789abcdef";
    for (uint8_t b : data) {
        env.push_back(hx[b >> 4]);
        env.push_back(hx[b & 0xF]);
    }
    env += "\"}";
    static const char* ua = steamcore::api::kUserAgent;
    std::string cookie = cf_cookie();
    return http_post(host_ + "/api/" + cmd,
                     std::vector<uint8_t>(env.begin(), env.end()), ua, cookie);
}

// Beta channel wrapper: auto-selects host once, then posts JSON envelope.
std::vector<uint8_t> beta_call(const std::string& cmd,
                              const std::vector<uint8_t>& data) {
    static BetaClient client = BetaClient::autoselect();
    return client.call(cmd, data);
}

}  // namespace api
}  // namespace steamcore
