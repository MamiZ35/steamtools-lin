// SteamCore - beta channel keys / endpoints (Faz 3)
// Beta channel is "CDN-direct": it auto-selects a host at runtime via the
// manifest "urls" list and talks JSON (SHA-1 envelope), NOT the Stable X-Proto-*
// signed gateway (see base/sub_1800137F0.c, sub_18003FC80.c, base/source/CoreBeta).
#pragma once
#include <string>
#include <vector>

namespace steamcore {
namespace api {

// ---------------------------------------------------------------------------
// Beta candidate hosts (recovered from the manifest "urls" array):
//   {"Version":6,"VersionTxt":"1.8","urls":[
//     "https://cdn-api-v2.tnkjmec.com","https://cdn-api-cc.tnkjmec.com",
//     "https://cdn-api.steamox.com"]}
// Host is auto-selected: POST <host>/api/test to each; first returning "1" wins.
// ---------------------------------------------------------------------------
inline constexpr const char* kBetaHosts[] = {
    "https://cdn-api-v2.tnkjmec.com",
    "https://cdn-api-cc.tnkjmec.com",
    "https://cdn-api.steamox.com",
    nullptr
};

// ---------------------------------------------------------------------------
// Beta manifest transport: direct, unsigned curl GET to
//   http://gmrc.wudrm.com/manifest/<appid>  (sub_1800436F0)
// Response body is the decimal manifest id (strtoull).
// ---------------------------------------------------------------------------
inline constexpr const char* kBetaManifestBase =
    "http://gmrc.wudrm.com/manifest/";
inline constexpr const char* kBetaManifestRef =
    "Referer: http://gmrc.wudrm.com";

}  // namespace api
}  // namespace steamcore
