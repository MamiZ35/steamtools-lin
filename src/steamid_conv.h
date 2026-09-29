// SteamCore - SteamID conversion helpers (01-userid closed)
//
//  Source: sub_180051810 case 768 -> sub_180010780 (Get_e_Ticket)
//          -> sub_1800381E0 (X-Proto-SteamID mask: 0x0110000100000000)
//          -> sub_180050F80 (protobuf body {appid, userid})
//
//  Proven invariance:
//      1. identity message (case 768) writes u32 to dword_1801E0614 (lpMem+9)
//      2. Get_e_Ticket (5527) reads that u32 as "userid" in request body
//      3. X-Proto-SteamID = u32 | 0x0110000100000000
//      4. qword_1801E0618 (lpMem+18) is a separate high-value varint,
//         NOT consumed by Get_e_Ticket (5527 uses only low32)
//
//  The conversion from SteamID64 -> SteamID32 (low32) and back is:
//      u32 steamid32 = static_cast<uint32_t>(steamid64);  // == & 0xFFFFFFFF
//      u64 steamid64 = static_cast<uint64_t>(steamid32) | 0x0110000100000000ULL;
//
//  This is exactly the decomp's conversion at sub_1800381E0 line 194:
//      *(_QWORD *)... = (QWORD)(low32) | 0x1100000000000000LL
#pragma once
#include <cstdint>
#include <string>

namespace steamcore {
namespace account {
    // Canonical SteamID64 mask: 0x0110000100000000 (individual account form)
    inline constexpr uint64_t kSteamid64Mask = 0x0110000100000000ULL;
    // The high32 component (for X-Proto-SteamID): 0x01100001
    inline constexpr uint64_t kSteamid64MaskHigh = 0x01100001ULL;

    // u64 SteamID64 -> u32 low32 (SteamID32 / "userid" in request body)
    // decomp: dword_1801E0614 = *(_DWORD *)((char*)lpMem + 9)
    inline uint32_t low32_of(uint64_t sid64) {
        return static_cast<uint32_t>(sid64);
    }

    // u32 low32 -> u64 SteamID64 (canonical form with mask)
    // decomp: sub_1800381E0 line 194
    inline uint64_t make_steamid64(uint32_t sid32) {
        return static_cast<uint64_t>(sid32) | kSteamid64Mask;
    }

    // u64 SteamID64 -> X-Proto-SteamID string (u64 canonical)
    inline std::string steamid64_to_string(uint64_t sid64) {
        return std::to_string(sid64);
    }

    // u32 low32 -> X-Proto-SteamID string (canonical u64 form)
    inline std::string steamid32_to_proto_string(uint32_t sid32) {
        return steamid64_to_string(make_steamid64(sid32));
    }

    // Parse a steamid64 from a decimal string.
    //   - If input <= 0xFFFFFFFF: treat as low32, return masked u64
    //   - If input has the 0x01100001... high32: return as-is (validate)
    //   - else return 0 (invalid)
    inline uint64_t steamid_parse(const std::string& in) {
        try {
            uint64_t v = static_cast<uint64_t>(std::stoull(in));
            if (v <= 0xFFFFFFFFULL) {
                return make_steamid64(static_cast<uint32_t>(v));
            }
            // high32 check: must be exactly the mask's high32
            if ((v & ~0xFFFFFFFFULL) != kSteamid64Mask) return 0;
            return v;
        } catch (...) { return 0; }
    }

    // u64 -> u32 string (for "userid" field in request body)
    inline std::string steamid32_from_u64(uint64_t sid64) {
        return std::to_string(low32_of(sid64));
    }

    // u32 -> X-Proto-SteamID string
    inline std::string steamid64_from_u32(uint32_t sid32) {
        return steamid32_to_proto_string(sid32);
    }

    // Round-trip verification helper (for tests): parse(u32) should give back u32
    inline bool steamid_roundtrip_ok(uint64_t sid64) {
        if (sid64 == 0) return true;
        if ((sid64 & ~0xFFFFFFFFULL) != kSteamid64Mask) return false;
        return make_steamid64(low32_of(sid64)) == sid64;
    }
}  // namespace account
}  // namespace steamcore