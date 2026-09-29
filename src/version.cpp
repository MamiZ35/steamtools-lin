// SteamCore - version (Linux port of version.cpp)
//   /version channel: AES-256-CBC + zlib (kVersionKey), fetch from the
//   recovered mirror list, then parse the JSON manifest.
//   Version computation: Bezier curve evaluation (seed -> version string).
#include "steamcore.h"
#include <curl/curl.h>
#include <cstring>
#include <cmath>
#include <cstdio>
#include <cstddef>
#include <algorithm>
#include <cctype>
#include <string>
#include <vector>
#include <stdexcept>

namespace steamcore {
namespace version {

// ---------------------------------------------------------------------------
// /version mirrors (recovered from Core.dll data section, base/README.md 3.2).
//   The first mirror that returns a decodable manifest wins.
// ---------------------------------------------------------------------------
const std::vector<std::string> kVersionMirrors = {
    "https://update.tnkjmec.com/version",
    "http://update.wudrm.com/version",
    "http://update.steamcdn.com/version",
};

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
    curl_easy_setopt(c, CURLOPT_TIMEOUT, 30L);
    // Real mirrors use a mix of http/https; allow both.
    CURLcode r = curl_easy_perform(c);
    curl_easy_cleanup(c);
    if (r != CURLE_OK) throw std::runtime_error(std::string("curl: ") + curl_easy_strerror(r));
    return buf;
}

}  // namespace (anon)

std::vector<uint8_t> fetch_version(const std::string& branch) {
    (void)branch;  // branch is selected post-decrypt, from the manifest body
    for (const auto& url : kVersionMirrors) {
        try {
            std::vector<uint8_t> enc = http_get(url);
            std::vector<uint8_t> dec = aes256cbc_zlib_decrypt(enc, kVersionKey);
            // A valid manifest is a JSON document (starts with '{' after optional
            // whitespace). Guard against the 301/HTML error pages that the
            // wrong mirrors return.
            if (dec.size() > 0) {
                auto it = std::find_if(dec.begin(), dec.end(),
                                      [](unsigned char c) {
                                          return c == '{';
                                      });
                if (it != dec.end()) return dec;
            }
        } catch (...) {
            // try next mirror
        }
    }
    throw std::runtime_error("all /version mirrors failed");
}

// Extract a quoted JSON string that follows `key` (used for top-level fields).
static std::string extract_json_str(const std::string& doc, const char* key) {
    std::string k = std::string("\"") + key + "\"";
    auto kp = doc.find(k);
    if (kp == std::string::npos) return "";
    auto cp = doc.find(':', kp + k.size());
    if (cp == std::string::npos) return "";
    // Skip to the next double-quote (string start).
    auto vs = doc.find('"', cp + 1);
    if (vs == std::string::npos) return "";
    auto ve = doc.find('"', vs + 1);
    if (ve == std::string::npos) return "";
    return doc.substr(vs + 1, ve - vs - 1);
}

// Extract the first integer following key in doc (e.g. "Version":6).
static bool extract_json_int(const std::string& doc, const char* key, int& out) {
    std::string k = std::string("\"") + key + "\"";
    auto kp = doc.find(k);
    if (kp == std::string::npos) return false;
    auto cp = doc.find(':', kp + k.size());
    if (cp == std::string::npos) return false;
    auto pos = cp + 1;
    while (pos < doc.size() && std::isspace(static_cast<unsigned char>(doc[pos]))) ++pos;
    int start = static_cast<int>(pos);
    if (pos < doc.size() && (doc[pos] == '-' || doc[pos] == '+')) {
        if (pos + 1 < static_cast<int>(doc.size())) ++pos; else return false;
    }
    while (pos < doc.size() && std::isdigit(static_cast<unsigned char>(doc[pos]))) ++pos;
    if (pos == static_cast<int>(start)) return false;
    std::string num = doc.substr(start, pos - start);
    out = std::atoi(num.c_str());
    return true;
}

// Extract a JSON string array following `key` (e.g. "urls":[ ... ]).
static std::vector<std::string> extract_json_str_array(const std::string& doc, const char* key) {
    std::vector<std::string> out;
    std::string k = std::string("\"") + key + "\"";
    auto kp = doc.find(k);
    if (kp == std::string::npos) return out;
    auto cp = doc.find(':', kp + k.size());
    if (cp == std::string::npos) return out;
    auto sa = cp + 1;
    while (sa < doc.size() && std::isspace(static_cast<unsigned char>(doc[sa]))) ++sa;
    if (sa < doc.size() && doc[sa] == '[') ++sa; else return out;
    auto close_br = doc.find(']', sa);
    if (close_br == std::string::npos) return out;
    // Walk the substring between '[' and ']' extracting quoted strings.
    std::string arr = doc.substr(sa, close_br - sa);
    auto pos = arr.find('"');
    while (pos != std::string::npos) {
        auto end = arr.find('"', pos + 1);
        if (end == std::string::npos) break;
        out.push_back(arr.substr(pos + 1, end - pos - 1));
        pos = arr.find('"', end + 1);
    }
    return out;
}

// Extract the entry object's field under the branch key, e.g.
//   "WindowsFile64Stable":[{"FileName":"...","URL":"https://update.steamcdn.com/Core",...}]
// Returns the `field` value of the first object inside the branch array.
static std::string extract_branch_field(const std::string& doc, const std::string& branch,
                                       const char* field) {
    std::string key = "\"" + branch + "\"";
    auto kp = doc.find(key);
    if (kp == std::string::npos) return "";
    // After the key there should be ':' then '{' or '['.
    auto sa = kp + key.size();
    auto cp = doc.find(':', sa);
    if (cp == std::string::npos) return "";
    auto arr_start = doc.find('[' , cp);
    if (arr_start == std::string::npos) return "";
    auto arr_end = doc.find(']', arr_start + 1);
    if (arr_end == std::string::npos) return "";
    std::string body = doc.substr(arr_start, arr_end - arr_start + 1);
    std::string fk = std::string("\"") + field + "\"";
    auto fkp = body.find(fk);
    if (fkp == std::string::npos) return "";
    auto fcp = body.find(':', fkp + fk.size());
    if (fcp == std::string::npos) return "";
    // value: find the first and next double-quote.
    auto vs = body.find('"', fcp + 1);
    if (vs == std::string::npos) return "";
    auto ve = body.find('"', vs + 1);
    if (ve == std::string::npos) return "";
    return body.substr(vs + 1, ve - vs - 1);
}

// Compute the URL's host (scheme://... -> host)
static std::string url_host(const std::string& u) {
    if (u.size() < 3) return u;
    // Skip scheme (http/https) up to "//"
    auto p2 = u.find("//", 0);
    size_t start = (p2 == std::string::npos) ? 0 : p2 + 2;
    auto e = u.find('/', start);
    if (e == std::string::npos) return u.substr(start);
    std::string host = u.substr(start, e - start);
    auto port = host.find(':');
    if (port != std::string::npos) host = host.substr(0, port);
    return host;
}

VersionInfo parse_manifest(const std::vector<uint8_t>& manifest,
                           const std::string& branch) {
    std::string doc(reinterpret_cast<const char*>(manifest.data()), manifest.size());
    VersionInfo info;
    info.branch = branch;

    // Extract top-level fields
    int version_int = 0;
    if (extract_json_int(doc, "Version", version_int))
        info.version = version_int;
    info.version_text = extract_json_str(doc, "VersionTxt");
    info.api_hosts = extract_json_str_array(doc, "urls");

    // Branch-specific fields
    std::string url = extract_branch_field(doc, branch, "URL");
    info.download_url = url;
    // host: use the first api host from manifest urls if available, otherwise
    //   derive from the branch url host.
    if (!info.api_hosts.empty()) {
        info.host = url_host(info.api_hosts[0]);
    } else {
        info.host = url.empty() ? "" : url_host(url);
    }
    return info;
}

// ---------------------------------------------------------------------------
// Bezier version computation
//   Reference: the original loader derives a version number via curve sampling.
//   Here a cubic Bezier with fixed endpoints (0,0)->(1,1) and internal control
//   points p1/p2 is sampled at the normalized seed to produce a version value,
//   then formatted as a "major.minor" version string.
// ---------------------------------------------------------------------------
// Evaluate a 2-point intermediate Bezier (endpoints (0,0) and (1,0)) for the
// y-channel used by the version computation. t is in [0,1].
double bezier_eval(const BezierPoint& p1, const BezierPoint& p2, double t) {
    double t1 = 1.0 - t;
    t1 = t1 < 0.0 ? 0.0 : (t1 > 1.0 ? 1.0 : t1);
    if (t < 0.0) t = 0.0;
    if (t > 1.0) t = 1.0;
    // Quadratic Bezier in y for the two intermediate control points.
    double y = t1 * t1 * p1.y + 2.0 * t1 * t * p2.y;
    return y;
}

std::string compute_version(uint32_t seed, const std::vector<BezierPoint>& pts) {
    // No curve points: the seed itself is the version identifier.
    if (pts.empty()) {
        return std::to_string(seed);
    }
    // Sample the curve at a normalized seed position to obtain the fractional
    // version, then present it as major.minor.
    double t = static_cast<double>(seed % 256) / 255.0;
    const auto& p1 = pts[0];
    const auto& p2 = pts.empty() ? pts[0] : pts[std::min<size_t>(1, pts.size()) - 1];
    double y = bezier_eval(p1, p2, t);
    // Ensure the version is always >= 0.
    if (y < 0.0) y = 0.0;
    char buf[64];
    int major = static_cast<int>(y);
    int minor = static_cast<int>((y - major) * 100.0);
    snprintf(buf, sizeof(buf), "%d.%02d", major, minor);
    return std::string(buf);
}

}  // namespace version
}  // namespace steamcore
