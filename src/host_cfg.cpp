// SteamCore - host configuration (02-manifest-hosts)
//
//   Separates the two concerns the reference keeps separate:
//     1) HOST DISCOVERY  -> manifest "urls" (host_cfg::api_hosts)
//     2) HOST SELECTION  -> per channel: stable = first; beta = autoselect probe
//
//   Reference: sub_18000B490 writes the manifest "urls" entry to a global
//   shared by the Stable client (sub_1800381E0) and the Beta client
//   (sub_18003FBA0 / sub_1800137F0 autoselect).  Live manifest (2026-09-28)
//   serves a NEWER host list than the recovered hardcoded one, so the manifest
//   is the authoritative discovery source; the recovered list is the OFFLINE
//   fallback so behaviour is unchanged when the manifest is unreachable.
#include "steamcore.h"
#include <string>
#include <vector>
#include <curl/curl.h>

namespace steamcore {
namespace api {

// Recovered hardcoded host list (original build / legacy port).  Used ONLY as
// the offline fallback when manifest discovery is unavailable.
std::vector<std::string> fallback_api_hosts() {
    return {
        "https://cdn-api-v2.tnkjmec.com",
        "https://cdn-api-cc.tnkjmec.com",
        "https://cdn-api.steamox.com",
    };
}

// Host DISCOVERY: fetch the /version manifest and read its "urls" field.
//   Cache is per-process (fetched at most once).  Returns the manifest hosts
//   when available, otherwise the recovered fallback list — callers always
//   receive a non-empty list.  Never throws.
static std::vector<std::string> g_cached_hosts;   // the list returned by api_hosts()
static bool                   g_loaded = false;

const std::vector<std::string>& api_hosts() {
    if (g_loaded) return g_cached_hosts;
    g_loaded = true;
    try {
        std::vector<uint8_t> ver = version::fetch_version("WindowsFile64Stable");
        VersionInfo info = version::parse_manifest(ver, "WindowsFile64Stable");
        if (!info.api_hosts.empty()) {
            g_cached_hosts = info.api_hosts;   // manifest "urls" (authoritative)
            return g_cached_hosts;
        }
    } catch (...) {
        // fall through to the recovered fallback below
    }
    g_cached_hosts = fallback_api_hosts();
    return g_cached_hosts;
}

// Strip a trailing '/' (and any leading 'http://'/'https://' is preserved).
static std::string strip_trailing_slash(std::string h) {
    while (!h.empty() && h.back() == '/') h.pop_back();
    return h;
}

// Host SELECTION (stable): FIRST resolved host + "/"  ->  the client POSTs to
//   <host>/api/<cmd>.  (decomp: stable base = manifest "urls" entry)
std::string api_base() {
    const std::vector<std::string>& hosts = api_hosts();
    if (hosts.empty()) return fallback_api_hosts()[0] + "/";
    return strip_trailing_slash(hosts.front()) + "/";
}

}  // namespace api
}  // namespace steamcore
