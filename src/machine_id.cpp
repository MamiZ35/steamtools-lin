// SteamCore - machine_id (Linux port of machine_id.cpp)
// Original uses cpuid + GetSystemInfo (Windows).  On Linux we use
//  - /proc/cpuinfo for vendor_id, family, model, processor count
// Same CRC64 over MD5 hex, same output format.
#include "steamcore.h"
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <cctype>
#include <cstring>
#include <unistd.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace steamcore {
namespace {

// CRC64 (poly 0x85E1C3D753D46D27), reflected, init 0.
uint64_t crc64(const uint8_t* data, size_t len) {
    uint64_t crc = 0;
    const uint64_t p = 0x85E1C3D753D46D27ULL;
    for (size_t i = 0; i < len; ++i) {
        crc ^= static_cast<uint64_t>(data[i]);
        for (int b = 0; b < 8; ++b) {
            if (crc & 1)
                crc = (crc >> 1) ^ p;
            else
                crc >>= 1;
        }
    }
    return crc;
}

// Read a value from /proc/cpuinfo given key name
static std::string read_cpuinfo(const char* key) {
    FILE* f = fopen("/proc/cpuinfo", "r");
    if (!f) return "";
    char line[4096]{};
    while (fgets(line, sizeof(line), f)) {
        // Find colon
        char* eq = strchr(line, ':');
        if (!eq) continue;
        // Build key
        std::string lkey(line);
        lkey = lkey.substr(0, static_cast<size_t>(eq - line));
        // trim lkey
        auto trim = [](std::string s) {
            size_t a = s.find_first_not_of(" \t\r\n");
            size_t b = s.find_last_not_of(" \t\r\n");
            if (a == std::string::npos) return std::string();
            return s.substr(a, b - a + 1);
        };
        lkey = trim(lkey);
        // Value is everything after colon
        std::string kvalue = eq + 1;
        kvalue = trim(kvalue);
        if (lkey == std::string(key)) {
            fclose(f);
            return kvalue;
        }
    }
    fclose(f);
    return "";
}

static int parse_int(const std::string& s) {
    try { return std::stoi(s); } catch (...) { return 0; }
}

}  // namespace (anon)

std::string machine_id() {
    std::string vendor = read_cpuinfo("vendor_id");
    if (vendor.empty()) vendor = "unknown";
    int family = parse_int(read_cpuinfo("cpu family"));
    int model  = parse_int(read_cpuinfo("model"));
    // Count unique processors from /proc/cpuinfo "processor:" lines
    int processors = static_cast<int>(sysconf(_SC_NPROCESSORS_ONLN));
    if (processors < 1) processors = 1;
    // Fallback: count processor entries
    {
        int c = 0;
        FILE* f = fopen("/proc/cpuinfo", "r");
        char buf[4096]{};
        while (f && fgets(buf, sizeof(buf), f)) {
            if (strncmp(buf, "processor", 9) == 0) c++;
        }
        if (f) fclose(f);
        if (c > 0) processors = c;
    }

    // Build the format string "V{vendor}_F{family:X}_M{model:X}_C{processors}"
    std::string fmt;
    fmt += "V";
    fmt += vendor;
    fmt += "_F";
    {
        char b[32]{};
        snprintf(b, sizeof(b), "%X", family);
        fmt += b;
    }
    fmt += "_M";
    {
        char b[32]{};
        snprintf(b, sizeof(b), "%X", model);
        fmt += b;
    }
    fmt += "_C";
    fmt += std::to_string(processors);

    std::string md5 = crypto::md5_hex(reinterpret_cast<const uint8_t*>(fmt.data()), fmt.size());
    uint64_t code = crc64(reinterpret_cast<const uint8_t*>(md5.data()), md5.size());
    char out[17];
    snprintf(out, sizeof(out), "%016llX", static_cast<unsigned long long>(code));
    return std::string(out);
}

}  // namespace steamcore