// SteamCore - complete public API (Linux port of SteamTools core)
// Mirrors reference structure (Core/include/steamcore): crypto, machine_id,
// version, core, api. C++17, ELF-native.
//
// Keys are recovered verbatim from the original Core.dll data section, so
// the crypto behavior is IDENTICAL to the original.  Backend is OpenSSL
// (reference used mbedTLS; same AES-256-CBC / AES-CTR / AES-CCM ops).
//
// Format observed in both channels (/version and core payload):
//   [ 16 bytes IV ][ AES-256-CBC ciphertext ][ 4 bytes LE size ][ zlib stream ]

#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>

#include "steamid_conv.h"  # 01-userid (CLOSED): SteamID conversion namespace

namespace steamcore {

// ---------------------------------------------------------------------------
// Binary keys recovered verbatim (hex) from Core.dll IDA data section.
//   unk_180083FF8 -> /version channel key
//   unk_180083FD8 -> Core/WindowsFile64Stable + CoreBeta key
// ---------------------------------------------------------------------------
extern const std::vector<uint8_t> kVersionKey;
extern const std::vector<uint8_t> kCoreKey;

// ---------------------------------------------------------------------------
// AES-256-CBC + zlib pipeline  (aes256cbc_zlib_* from crypto.cpp)
// ---------------------------------------------------------------------------
std::vector<uint8_t> aes256cbc_zlib_decrypt(const std::vector<uint8_t>& blob,
                                            const std::vector<uint8_t>& key);
std::vector<uint8_t> aes256cbc_zlib_encrypt(const std::vector<uint8_t>& plain,
                                            const std::vector<uint8_t>& key);

// ---------------------------------------------------------------------------
// Stable channel API client
// ---------------------------------------------------------------------------
namespace api {
// User-Agent recovered from the original SteamTools (base/scripts/*).
// This is the value the native binary sends to the API gateway.
inline constexpr const char* kUserAgent = "SteamTools/3.0";

// ---------------------------------------------------------------------------
// API host configuration (02-manifest-hosts) — see src/host_cfg.cpp
//   Separates host DISCOVERY (manifest "urls") from per-channel SELECTION.
//   api_hosts()  -> resolved host list (manifest "urls" if available, else
//                   the recovered hardcoded fallback; cached per-process)
//   api_base()   -> stable base = first resolved host + "/"
//                   (decomp: stable base = manifest "urls" entry)
// ---------------------------------------------------------------------------
std::vector<std::string> fallback_api_hosts();   // recovered hardcoded list
const std::vector<std::string>& api_hosts();     // resolved list (manifest or fallback)
std::string api_base();                          // stable base = first resolved host

struct SteamClientApi {
    // Base is derived from the manifest "urls" when available, else
    // the recovered hardcoded fallback.  (see api_base())
    static const char* base() {
        return api_base().c_str();
    }
};

class StableClient {
 public:
    explicit StableClient(std::string host);
    std::vector<uint8_t> call(const std::string& cmd,
                             const std::string& steamid,
                             const std::vector<uint8_t>& body,
                             bool* out_cf_challenge = nullptr);
 private:
    std::string host_;
    std::unordered_map<std::string, std::string> base_headers_;
};

// Manifest (beta CDN-direct): GET http://gmrc.wudrm.com/manifest/<appid>
namespace manifest {
    uint64_t fetch_manifest_id(uint32_t appid);
}  // namespace manifest
}  // namespace api
namespace api {
    std::vector<uint8_t> call(const std::string& cmd,
                             const std::vector<uint8_t>& body);
}  // namespace api

// ---------------------------------------------------------------------------
// Additional crypto (AES-CTR / AES-CCM / SHA-256 / MD5 / base64) from
// reference (crypto.cpp stable + beta parts).
// ---------------------------------------------------------------------------
namespace crypto {
    void aes_ctr_decrypt(const uint8_t* data, size_t len, const uint8_t* key_iv, uint8_t* out);
    void aes_ccm_decrypt(const uint8_t* data, size_t len, const uint8_t* key,
                         const uint8_t* nonce, const uint8_t* aad, size_t aad_len,
                         uint8_t* tag_out16, uint8_t* out);
    void sha256(const uint8_t* data, size_t len, uint8_t* out32);
    std::string sha256_hex(const uint8_t* data, size_t len);
    void sha1(const uint8_t* data, size_t len, uint8_t* out20);
    std::string sha1_hex(const uint8_t* data, size_t len);
    std::string md5_hex(const uint8_t* data, size_t len);
    std::string base64_encode(const uint8_t* data, size_t len);
    std::vector<uint8_t> base64_decode(const char* data, size_t len);
    std::vector<uint8_t> zlib_inflate(const uint8_t* data, size_t len);
    std::vector<uint8_t> zlib_inflate(const std::vector<uint8_t>& compressed);
    std::vector<uint8_t> zlib_deflate(const std::vector<uint8_t>& in);
}  // namespace crypto

// ---------------------------------------------------------------------------
// Beta channel API client (JSON + mbedTLS/SHA-1 envelope)
// ---------------------------------------------------------------------------
namespace api {
    class BetaClient {
    public:
        static const std::vector<std::string>& candidate_hosts();
        static BetaClient autoselect();
        explicit BetaClient(std::string host);
        std::vector<uint8_t> call(const std::string& cmd,
                                 const std::vector<uint8_t>& data);
    private:
        std::string host_;
    };

    // Beta channel wrapper: auto-selects host once, then posts JSON envelope.
    std::vector<uint8_t> beta_call(const std::string& cmd,
                                  const std::vector<uint8_t>& data);
}  // namespace api

// ---------------------------------------------------------------------------
// Steam account (steamid64) — read from local Steam config
// ---------------------------------------------------------------------------
std::string get_current_steamid();  // steamid64 of currently-logged-in user

// ---------------------------------------------------------------------------
// Version (Bezier + fetch/parse)
// ---------------------------------------------------------------------------
struct BezierPoint { float x, y; };
struct VersionInfo {
    std::string branch;
    std::string download_url;
    std::string host;
    int version = 0;                 // manifest "Version" field
    std::string version_text;        // manifest "VersionTxt" field
    std::vector<std::string> api_hosts;
};
namespace version {
    double bezier_eval(const BezierPoint& p1, const BezierPoint& p2, double t);
    std::string compute_version(uint32_t seed, const std::vector<BezierPoint>& pts);
    extern const std::vector<std::string> kVersionMirrors;
    std::vector<uint8_t> fetch_version(const std::string& branch = "WindowsFile64Stable");
    VersionInfo parse_manifest(const std::vector<uint8_t>& manifest,
                              const std::string& branch);
}  // namespace version

// ---------------------------------------------------------------------------
// Core payload
// ---------------------------------------------------------------------------
struct CorePayload {
    std::vector<uint8_t> pe;   // decrypted payload
};
std::vector<uint8_t> fetch_core_from(const std::string& url);

// ---------------------------------------------------------------------------
// machine_id
// ---------------------------------------------------------------------------
std::string machine_id();

}  // namespace steamcore