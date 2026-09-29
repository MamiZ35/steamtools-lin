// SteamCore - manifest (Linux port of api/manifest.cpp)
#include "steamcore.h"
#include <curl/curl.h>
#include <cstdlib>
#include <stdexcept>
#include <string>
#include <vector>

namespace steamcore {
namespace {
size_t write_cb(void* ptr, size_t size, size_t nmemb, void* user) {
    auto* v = static_cast<std::vector<uint8_t>*>(user);
    size_t real = size * nmemb;
    v->insert(v->end(), static_cast<uint8_t*>(ptr),
              static_cast<uint8_t*>(ptr) + real);
    return real;
}
}  // namespace (anon)
namespace api {
namespace manifest {
uint64_t fetch_manifest_id(uint32_t appid) {
    std::string url = "http://gmrc.wudrm.com/manifest/" + std::to_string(appid);
    std::vector<uint8_t> resp;
    CURL* c = curl_easy_init();
    if (!c) throw std::runtime_error("curl init");
    curl_slist* hdr = curl_slist_append(nullptr, "Referer: gmrc.wudrm.com");
    curl_easy_setopt(c, CURLOPT_URL, url.c_str());
    curl_easy_setopt(c, CURLOPT_HTTPHEADER, hdr);
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, &resp);
    curl_easy_setopt(c, CURLOPT_TIMEOUT, 30L);
    CURLcode r = curl_easy_perform(c);
    curl_slist_free_all(hdr);
    curl_easy_cleanup(c);
    if (r != CURLE_OK) throw std::runtime_error(curl_easy_strerror(r));
    std::string body(reinterpret_cast<const char*>(resp.data()), resp.size());
    return std::strtoull(body.c_str(), nullptr, 10);
}
}  // namespace manifest
}  // namespace api
}  // namespace steamcore