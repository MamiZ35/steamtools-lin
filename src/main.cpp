// CLI - SteamTools Linux core (offline + online mode)
#include "steamcore.h"
#include "appids_db.h"
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

namespace {

std::vector<uint8_t> read_file(const char* path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error(std::string("cannot open ") + path);
    return std::vector<uint8_t>(
        std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
}

bool is_valid_elf(const std::vector<uint8_t>& buf) {
    if (buf.size() < 16) return false;
    return buf[0] == 0x7F && buf[1] == 'E' && buf[2] == 'L' && buf[3] == 'F';
}

}  // namespace

// Usage:
//   ./core_cli                          (self-test: machine_id + crypto round-trip)
//   ./core_cli version                  (download /version blob, decrypt, parse)
//   ./core_cli core <blob.bin>           (decrypt a local /core blob)
//   ./core_cli manifest <appid>          (fetch manifest id for appid)
//   ./core_cli appids                   (list all registered appids)
//   ./core_cli appids add <appid>        (register appid + get depskey)
//   ./core_cli appids key <appid>        (get depot_key for appid)
//   ./core_cli appids keygen             (compute machine_key from machine_id)
//   ./core_cli eticket <appid>           (get e-Ticket for appid)
//   ./core_cli eticket <appid> <channel> (channel: stable|beta)
//   ./core_cli steamid                   (read current steamid64)

int main(int argc, char** argv) {
    try {
        std::cout << "[SteamCore/Linear] machine_id: " << steamcore::machine_id() << "\n";

        // --- Crypto round-trip test (proves identical keys / pipeline) ---
        {
            std::string sample("SteamTools Linux port - AES-256-CBC + zlib pipeline");
            std::vector<uint8_t> enc = steamcore::aes256cbc_zlib_encrypt(
                std::vector<uint8_t>(sample.begin(), sample.end()), steamcore::kCoreKey);
            auto dec = steamcore::aes256cbc_zlib_decrypt(enc, steamcore::kCoreKey);
            bool ok = (dec == std::vector<uint8_t>(sample.begin(), sample.end()));
            std::cout << "[Crypto] AES-256-CBC + zlib round-trip: "
                      << (ok ? "PASS (encrypt/decrypt identical)" : "FAIL") << "\n";
            std::cout << "[Crypto] kVersionKey size = " << steamcore::kVersionKey.size()
                      << " bytes, kCoreKey size = " << steamcore::kCoreKey.size()
                      << " bytes\n";
        }

        if (argc > 1 && std::string(argv[1]) == "version") {
            std::cout << "[Version] fetching /version ...\n";
            auto ver = steamcore::version::fetch_version("WindowsFile64Stable");
            std::cout << "[Version] decrypted manifest: " << ver.size() << " bytes\n";
            auto info = steamcore::version::parse_manifest(ver, "WindowsFile64Stable");
            std::cout << "[Version] branch       = " << info.branch << "\n";
            std::cout << "[Version] download_url = " << info.download_url << "\n";
            std::cout << "[Version] host         = " << info.host << "\n";
        } else if (argc > 1 && std::string(argv[1]) == "core") {
            if (argc < 3) {
                std::cout << "Usage: core_cli core <blob.bin>\n";
                return 2;
            }
            auto enc = read_file(argv[2]);
            auto dec = steamcore::aes256cbc_zlib_decrypt(enc, steamcore::kCoreKey);
            std::cout << "blob -> " << dec.size() << " bytes, "
                      << (is_valid_elf(dec) ? "valid ELF64" : "payload") << "\n";
        } else if (argc > 1 && std::string(argv[1]) == "manifest") {
            if (argc < 3) {
                std::cout << "Usage: core_cli manifest <appid>\n";
                return 2;
            }
            uint32_t appid = std::stoul(argv[2]);
            std::cout << "[Manifest] fetching manifest id for appid " << appid << " ...\n";
            auto id = steamcore::api::manifest::fetch_manifest_id(appid);
            std::cout << "[Manifest] manifest_id = " << id << "\n";
        } else if (argc > 1 && std::string(argv[1]) == "appids") {
            std::cout << "[AppIds] db path: " << steamcore::appids::db_path() << " ...\n";
            if (argc < 3) {
                std::cout << "  Listing all appids ...\n";
                auto apps = steamcore::appids::list_all();
                std::cout << "  count = " << apps.size() << " appid(s)\n";
                for (auto aid : apps) std::cout << "    " << aid << "\n";
            } else {
                std::string action = argv[2];
                if (action == "add" || action == "register") {
                    if (argc < 4) {
                        std::cout << "Usage: core_cli appids add <appid>\n";
                        return 2;
                    }
                    uint32_t appid = std::stoul(argv[3]);
                    std::cout << "[AppIds] registering appid " << appid << " ...\n";
                    auto rec = steamcore::appids::get_depots_key(appid);
                    if (rec.appid != 0) {
                        std::cout << "  depot_key = " << rec.key << " (len="
                                  << rec.key.size() << ")\n";
                    } else {
                        std::cout << "  FAILED (see API log)\n";
                    }
                    auto apps = steamcore::appids::list_all();
                    std::cout << "  total known appids now = " << apps.size() << "\n";
                    for (auto a : apps) std::cout << "    " << a << "\n";
                } else if (action == "key" || action == "depotskey") {
                    if (argc < 4) {
                        std::cout << "Usage: core_cli appids key <appid>\n";
                        return 2;
                    }
                    uint32_t appid = std::stoul(argv[3]);
                    auto rec = steamcore::appids::get_depots_key(appid);
                    if (rec.appid != 0) {
                        std::cout << "  depot_key = " << rec.key << "\n";
                    } else {
                        std::cout << "  not found\n";
                    }
                } else if (action == "keygen") {
                    std::string mid = steamcore::machine_id();
                    std::cout << "  machine_id = " << mid << "\n";
                    std::cout << "  sha256_hex(mid) = "
                              << steamcore::crypto::sha256_hex(
                                  reinterpret_cast<const uint8_t*>(mid.c_str()), mid.size()) << "\n";
                } else {
                    std::cout << "Usage: appids [add|key|keygen] <appid>?\n";
                    return 2;
                }
            }
        } else if (argc > 1 && std::string(argv[1]) == "eticket") {
            if (argc < 3) {
                std::cout << "Usage: core_cli eticket <appid> [stable|beta]\n";
                std::cout << "[e-Ticket] reads current steamid from "
                          << (getenv("HOME") ? getenv("HOME") : ".")
                          << "/.config/Steam/loginusers.vdf\n";
                return 2;
            }
            uint32_t appid = std::stoul(argv[2]);
            std::string channel = (argc > 3) ? std::string(argv[3]) : "stable";
            std::string sid = steamcore::get_current_steamid();
            std::cout << "[e-Ticket] appid = " << appid
                      << "  channel = " << channel << "\n";
            std::cout << "[e-Ticket] steamid = "
                      << (sid.empty() ? "(none)" : sid) << "\n";
            auto res = steamcore::ticket::get_eticket(appid, channel);
            if (res.ok) {
                std::cout << "  e_ticket (hex) = " << res.eticket_b64.substr(0, 40)
                          << (res.eticket_b64.size() > 40 ? "..." : "") << "\n";
                std::cout << "  e_ticket hex length = " << res.eticket_b64.size()
                          << " hex chars (decoded = "
                          << (res.eticket_b64.size() / 2) << " bytes)\n";
            } else {
                std::cout << "  FAILED\n";
                if (channel == "beta") {
                    std::cout << "  Beta channel: auto-selects first host\n";
                    std::cout << "  that returns '1' from POST /api/test.\n";
                } else {
                    std::cout << "  The live API is behind Cloudflare's JS-challenge (403).\n";
                    std::cout << "  Supply a solved CF cookie via STEAMTOOLS_CF_COOKIE\n";
                    std::cout << "  (see scripts/cf_solve.py) to get a real e-Ticket.\n";
                }
            }
        } else if (argc > 1 && std::string(argv[1]) == "hosts") {
            // 02-manifest-hosts: print the resolved API host list
            // (manifest "urls" when available, else recovered fallback).
            std::cout << "[Hosts] resolved API hosts:\n";
            const std::vector<std::string>& hosts = steamcore::api::api_hosts();
            for (size_t i = 0; i < hosts.size(); ++i)
                std::cout << "  [" << i << "] " << hosts[i] << "\n";
            std::cout << "[Hosts] stable base = " << steamcore::api::api_base()
                      << "\n";
        } else if (argc > 1 && std::string(argv[1]) == "steamid") {
            std::string sid = steamcore::get_current_steamid();
            std::cout << "[SteamID] current steamid = "
                      << (sid.empty() ? "(none found)" : sid) << "\n";
        }
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    }
}
