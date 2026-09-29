// SteamCore - appids_db + e-Ticket (Faz 2)
// Reference: sub_18004A2C0_sqlite_getdepotskey.c, sub_18004DF60_addappid.c,
//             sub_180010780_Get_e_Ticket.c
#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace steamcore {

// ---------------------------------------------------------------------------
// SQLite appids_db (app_list)
// DB path: $XDG_DATA_HOME/SteamTools/appids.db
// Schema:  app_list (AppID INTEGER PRIMARY KEY, key TEXT)
// ---------------------------------------------------------------------------
namespace appids {

struct AppRecord {
    uint32_t appid = 0;  // 0 = not found / not yet added
    std::string key;
};

std::string get_db_path();
AppRecord  get_depots_key(uint32_t appid);   // check/insert + GetDepotsKey API
void        add(uint32_t appid);             // addappid (sub_18004DF60)
std::vector<uint32_t> list_all();
std::string db_path();                        // returns current db path
void        close_db();
// Unlock trigger (sub_180010320) — sets an appid as "unlocked" in-memory.
bool        is_unlocked(uint32_t appid);
void        set_unlocked(uint32_t appid);

}  // namespace appids

// ---------------------------------------------------------------------------
// e-Ticket (sub_180010780_Get_e_Ticket)
// Flow:
//   1. Read loginusers.vdf for the first valid username
//   2. Build protobuf { username } (type 0)
//   3. POST to API Get_e_Ticket (stable: kCoreKey AES-256-CBC+zlib)
//      Response: {"eTicket": <base64>}
//   4. Base64-decode + zlib-inflate + AES-256-CCM-decrypt (16-byte tag stripped)
//      + zlib-inflate  => ticket content
//      (128 bytes: first 128 = base64-decoded eTicket for appid N)
//
// Beta channel: Get_e_Ticket_beta (AES-256-CTR/CCM, 16-byte tag stripped
//               before CCM decrypt, then zlib + base64-decode + zlib-inflate)
//
// ticket_size: 128 bytes per appid.  For DLC, multiple appids in one request.
// ---------------------------------------------------------------------------
namespace ticket {

struct TicketResult {
    bool ok = false;
    std::string eticket_b64;   // base64 eTicket (raw, from API response)
    std::string appid_key;    // base64 key (for DLC)
};

// LoginUsers read from Steam
std::string read_login_users();

// Fetch e-Ticket for a single appid (stable channel)
TicketResult get_eticket(uint32_t appid);

// Fetch e-Ticket on a given channel ("stable" | "beta")
TicketResult get_eticket(uint32_t appid, const std::string& channel);

// Fetch e-Ticket with DLC: multiple appids, one request
TicketResult get_eticket_dlc(uint32_t base_appid,
                             const std::vector<uint32_t>& dlc_appids);

}  // namespace ticket
}  // namespace steamcore