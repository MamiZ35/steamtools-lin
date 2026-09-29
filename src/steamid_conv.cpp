// SteamCore - SteamID conversion (01-userid closed)
//
//  All helpers are `inline` in steamid_conv.h, so this file is a thin
//  definition layer that exists primarily for symbol generation / ODR
//  safety.  In practice, the header alone is sufficient.
#include "steamid_conv.h"
#include <cstdio>
#include <iostream>
#include <string>
#include <vector>

namespace steamcore {
namespace account {
    // These are all inline in the header; this .cpp exists so the
    // linker has a translation unit that *includes* steamid_conv.h
    // (guarantees the header is compiled once, and gives us a place
    // to put any non-inline helpers added later).

    // X-Proto-SteamID string (u64 canonical form) from a u32.
    // (inline in .h)
    std::string steamid32_to_proto_string_impl(uint32_t sid32) {
        return steamid32_to_proto_string(sid32);
    }

    // SteamID64 string from a u64.
    std::string steamid64_to_string_impl(uint64_t sid64) {
        return steamid64_to_string(sid64);
    }

}  // namespace account
}  // namespace steamcore