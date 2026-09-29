// SteamCore - appids_db (SQLite3 app_list)
// Reference: sub_18004A2C0_sqlite_getdepotskey.c + sub_18004DF60_addappid.c
// DB path: ~/.local/share/SteamTools/appids.db  (Linux convention)
// Schema:  app_list (AppID INTEGER PRIMARY KEY, key TEXT)
#include "steamcore.h"
#include "appids_db.h"
#include <string>
#include <vector>
#include <fstream>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <climits>
#include <algorithm>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <sqlite3.h>

namespace steamcore {
namespace appids {

static sqlite3* g_db_ = nullptr;
static std::vector<uint32_t> g_unlocked;

std::string get_db_path() {
    const char* xd = std::getenv("XDG_DATA_HOME");
    std::string dir;
    if (xd && xd[0]) {
        dir = std::string(xd) + "/SteamTools";
    } else {
        const char* home = std::getenv("HOME");
        dir = std::string(home ? home : ".") + "/.local/share/SteamTools";
    }
    return dir + "/appids.db";
}

std::string compute_machine_key(const std::string& mid) {
    return crypto::sha256_hex(reinterpret_cast<const uint8_t*>(mid.c_str()), mid.size());
}

std::string init_db() {
    std::string path = get_db_path();
    size_t slash = path.rfind('/');
    if (slash != std::string::npos) {
        std::string parent = path.substr(0, slash);
        int rc = std::system(("mkdir -p '" + parent + "'").c_str());
        (void)rc;
    }
    sqlite3* db = nullptr;
    int rc = sqlite3_open(path.c_str(), &db);
    if (rc != SQLITE_OK) {
        std::string err = sqlite3_errmsg(db);
        sqlite3_close(db);
        return err;
    }
    const char* schema =
        "CREATE TABLE IF NOT EXISTS app_list ("
        "  AppID INTEGER PRIMARY KEY,"
        "  key TEXT"
        ");";
    char* serr = nullptr;
    rc = sqlite3_exec(db, schema, nullptr, nullptr, &serr);
    if (serr) {
        std::string err = serr;
        sqlite3_free(serr);
        sqlite3_close(db);
        return err;
    }
    g_db_ = db;
    return "";
}

AppRecord get_depots_key(uint32_t appid) {
    AppRecord rec;
    rec.appid = 0;
    rec.key = "";
    if (!g_db_) init_db();
    std::string query = "SELECT AppID, key FROM app_list WHERE AppID = " + std::to_string(appid);
    sqlite3_stmt* stmt = nullptr;
    bool found = false;
    if (sqlite3_prepare_v2(g_db_, query.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            rec.appid = static_cast<uint32_t>(sqlite3_column_int64(stmt, 0));
            rec.key = std::string((const char*)sqlite3_column_text(stmt, 1));
            found = true;
        }
        sqlite3_finalize(stmt);
    }
    if (!found) {
        // Not in DB yet -> register locally (SteamTools API call is best-effort)
        std::string mid = machine_id();
        std::string key = compute_machine_key(mid);
        std::string body = "{\"appid\":" + std::to_string(appid) +
                           ",\"key\":\"" + key + "\"}";
        try {
            api::call("GetDepotsKey",
                      std::vector<uint8_t>(body.begin(), body.end()));
        } catch (const std::exception&) {}
        std::string insq = "INSERT OR REPLACE INTO app_list (AppID, key) VALUES (?, ?)";
        sqlite3_stmt* ins = nullptr;
        if (sqlite3_prepare_v2(g_db_, insq.c_str(), -1, &ins, nullptr) == SQLITE_OK) {
            sqlite3_bind_int64(ins, 1, (int64_t)appid);
            sqlite3_bind_text(ins, 2, key.c_str(), (int64_t)key.size(), SQLITE_STATIC);
            if (sqlite3_step(ins) == SQLITE_OK) {
                rec.appid = appid;
                rec.key = key;
                set_unlocked(appid);
            }
            sqlite3_finalize(ins);
        }
    }
    return rec;
}

std::vector<uint32_t> list_all() {
    std::vector<uint32_t> apps;
    if (!g_db_) init_db();
    std::string query = "SELECT AppID FROM app_list";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(g_db_, query.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            apps.push_back(static_cast<uint32_t>(sqlite3_column_int64(stmt, 0)));
        }
        sqlite3_finalize(stmt);
    }
    return apps;
}

void add(uint32_t appid) {
    get_depots_key(appid);
}

std::string db_path() {
    return get_db_path();
}

void close_db() {
    if (g_db_) {
        sqlite3_close(g_db_);
        g_db_ = nullptr;
    }
}

bool is_unlocked(uint32_t appid) {
    return std::find(g_unlocked.begin(), g_unlocked.end(), appid) != g_unlocked.end();
}

void set_unlocked(uint32_t appid) {
    g_unlocked.push_back(appid);
}

}  // namespace appids
}  // namespace steamcore