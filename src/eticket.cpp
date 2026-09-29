// SteamCore - e-Ticket (Faz 2)
// Reference: sub_180010780_Get_e_Ticket.c (Stable Get_e_Ticket)
//   - Build JSON {appid, userid, name}
//   - POST /api  Get_e_Ticket  (stable client: AES-256-CBC+zlib body,
//     X-Proto-* headers, SHA-256 sig)
//   - Response: {"eTicket": <base64>}
//   - Process: base64_decode -> zlib_inflate -> 128-byte ticket
//
// Reference: sub_180045B30_Get_e_Ticket_beta.c (Beta)
//   - JSON {appid, userid}; API Get_e_Ticket (beta client)
//   - Response: steamid + e_ticket (hex)
//
// Reference: sub_18004FF60_protobuf_profile.c (DLC)
//   - For DLC: one ticket per appid, write to appcache
#include "steamcore.h"
#include "appids_db.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <fstream>
#include <algorithm>
#include <cctype>
#include <iostream>

namespace steamcore {

namespace ticket {

// ---------------------------------------------------------------------------
// Read first username + steamid from loginusers.vdf
//   Linux path: $HOME/.local/share/Steam/config/loginusers.vdf
//   VDF format (both old and new):
//     "LoginUsers" { <sid> { ... } }
//     "users"      { "76561199024350629" { ... } }
//   Returns steamid64
// ---------------------------------------------------------------------------
struct LoginInfo {
    std::string username = "";
    std::string steamid = "";
};

// Extract the first JSON string value for field `key` from raw JSON text.
static std::string extract_str(const std::string& json, const std::string& field) {
    std::string k = "\"";
    k += field;
    k += "\"";
    size_t kp = json.find(k);
    if (kp == std::string::npos) return "";
    // Find ':' after the key.
    size_t cp = json.find(':', kp + k.size());
    if (cp == std::string::npos) return "";
    // Find value string start/end.
    size_t vs = json.find("\"", cp + 1);
    size_t ve = json.find("\"", vs + 1);
    if (vs == std::string::npos || ve == std::string::npos) return "";
    return json.substr(vs + 1, ve - vs - 2);
}

// Strip everything that is not a hex digit, so the value is a clean hex string.
static std::string normalize_hex(const std::string& in) {
    std::string out;
    out.reserve(in.size());
    for (char c : in) {
        if (c >= '0' && c <= '9') out.push_back(c);
        else if (c >= 'a' && c <= 'f') out.push_back(c);
        else if (c >= 'A' && c <= 'F') out.push_back(c);
    }
    return out;
}

static std::string read_login_vdf(const std::string& path) {
    std::ifstream f(path.c_str(), std::ios::binary);
    if (!f) return "";
    std::string content((std::istreambuf_iterator<char>(f)),
                        std::istreambuf_iterator<char>());

    size_t start_pos = 0;
    const char* keywords[] = {"users", "LoginUsers", "loginusers"};
    for (const char* kw : keywords) {
        std::string quoted = "\"" + std::string(kw) + "\"";
        size_t kp = content.find(quoted);
        if (kp == std::string::npos) {
            kp = content.find(kw);
        }
        if (kp != std::string::npos) {
            start_pos = content.find('{', kp);
            if (start_pos == std::string::npos) return "";
            break;
        }
    }
    if (start_pos == std::string::npos) return "";
    size_t pos = start_pos + 1;

    // Scan forward for a 10-19 digit sequence (the steamid)
    while (pos < content.size()) {
        while (pos < content.size() && std::isspace(static_cast<unsigned char>(content[pos])))
            pos++;
        size_t ds = pos;
        size_t de = pos;
        while (de < content.size() && std::isdigit(static_cast<unsigned char>(content[de])))
            de++;
        size_t digits = de - ds;
        if (digits >= 10 && digits <= 19) {
            return content.substr(ds, digits);
        }
        if (de == ds) pos++; else pos = de;
    }
    return "";
}

LoginInfo read_login_info() {
    LoginInfo li;
    const char* home = getenv("HOME");
    std::vector<std::string> paths;
    if (home) {
        std::string h(home);
        paths.push_back(h + "/.local/share/Steam/config/loginusers.vdf");
        paths.push_back(h + "/.config/Steam/loginusers.vdf");
        paths.push_back(h + "/.local/share/Steam/loginusers.vdf");
    }
    const char* cfg = getenv("STEAM_CONFIG_DIR");
    if (cfg) paths.push_back(std::string(cfg) + "/loginusers.vdf");
    const char* appdata = getenv("STEAM_APPDATA");
    if (appdata) paths.push_back(std::string(appdata) + "/loginusers.vdf");

    for (const auto& pp : paths) {
        li.steamid = read_login_vdf(pp);
        if (li.steamid.empty()) continue;
        // Try to get username
        std::ifstream f(pp.c_str());
        if (f) {
            std::string content((std::istreambuf_iterator<char>(f)),
                                std::istreambuf_iterator<char>());
            size_t nk = content.find("\"name\"");
            if (nk != std::string::npos) {
                size_t vs = content.find('"', nk + 6);
                size_t ve = content.find('"', vs + 1);
                if (vs != std::string::npos && ve != std::string::npos) {
                    li.username = content.substr(vs + 1, ve - vs - 2);
                }
            }
            break;
        }
    }
    return li;
}

// ---------------------------------------------------------------------------
// Get e-Ticket
// ---------------------------------------------------------------------------
// get_eticket(appid)            -> stable channel (X-Proto* signed gateway)
// get_eticket(appid, channel)   -> "stable" | "beta" (JSON SHA-1 envelope)
TicketResult get_eticket(uint32_t appid) {
    return get_eticket(appid, "stable");
}

TicketResult get_eticket(uint32_t appid, const std::string& channel) {
    TicketResult res;
    res.ok = false;

    LoginInfo li = read_login_info();
    std::string steamid = li.steamid.empty() ? "1" : li.steamid;

    std::string body = "{\"appid\":" + std::to_string(appid);
    body += ",";
    body += "\"userid\":";
    body += steamid;
    body += "\"";
    if (!li.username.empty()) {
        body += ",\"name\":\"";
        body += li.username;
        body += "\"";
    }
    body += "}";

    std::vector<uint8_t> resp;
    try {
        if (channel == "beta") {
            resp = api::beta_call("Get_e_Ticket",
                                 std::vector<uint8_t>(body.begin(), body.end()));
        } else {
            resp = api::call("Get_e_Ticket",
                             std::vector<uint8_t>(body.begin(), body.end()));
        }
    } catch (const std::exception& ex) {
        return res;
    }

    std::string content(resp.begin(), resp.end());

    // Parse JSON — response:
    //   Stable: {"eTicket": <base64>} / {"steamid": ..., "e_ticket": "<hex>"}
    //   Beta:   {"steamid": <u32>, "e_ticket": "<hex>"}
    std::string e_hex = extract_str(content, "e_ticket");
    std::string e_key = extract_str(content, "appid_key");
    if (e_hex.empty() && !e_key.empty()) e_hex = e_key;
    if (e_hex.empty()) {
        std::string e_b64 = extract_str(content, "eTicket");
        std::string e_b64key = extract_str(content, "e_ticket");
        if (!e_b64key.empty()) e_hex = e_b64key;
        else if (!e_b64.empty()) e_hex = e_b64;
    }
    if (e_hex.empty()) return res;

    // Hex-decode the e_ticket (per reference: sub_180010780, pair-wise strtoul).
    // Fallback: if it looks like base64 (not pure hex) treat it as base64.
    bool is_hex = true;
    for (char c : e_hex) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
              (c >= 'A' && c <= 'F'))) { is_hex = false; break; }
    }
    std::vector<uint8_t> ticket;
    if (is_hex) {
        std::string h = normalize_hex(e_hex);
        auto hexv = [](char c) -> int {
            if (c >= '0' && c <= '9') return static_cast<int>(c - '0');
            if (c >= 'a' && c <= 'f') return static_cast<int>(c - 'a') + 10;
            if (c >= 'A' && c <= 'F') return static_cast<int>(c - 'A') + 10;
            return -1;
        };
        ticket.resize(h.size() / 2);
        for (size_t i = 0; i + 1 < h.size(); i += 2) {
            int hi = hexv(h[i]);
            int lo = hexv(h[i + 1]);
            if (hi >= 0 && lo >= 0)
                ticket[i / 2] = static_cast<uint8_t>((hi << 4) | lo);
        }
    } else {
        ticket = crypto::base64_decode(e_hex.c_str(), e_hex.size());
    }
    if (ticket.size() >= 16) {
        res.ok = true;
        res.eticket_b64 = e_hex;
        res.appid_key = e_hex;
        return res;
    }
    return res;
}

TicketResult get_eticket_dlc(uint32_t base_appid,
                             const std::vector<uint32_t>& dlc_appids) {
    (void)dlc_appids;
    return get_eticket(base_appid);
}

}  // namespace ticket

std::string get_current_steamid() {
    ticket::LoginInfo li = ticket::read_login_info();
    return li.steamid;
}

}  // namespace steamcore
