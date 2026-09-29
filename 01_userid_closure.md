# 01-userid - CLOSURE (branch CLOSED)
#
# Branch status: CLOSED (all 4 closure criteria met)
#   source      = protobuf/identity message, case 768, lpMem+9 (u32 low32)
#   raw value   = uint32 (proven: *(_DWORD *)((char*)lpMem + 9))
#   semantic    = SteamID low32 (proven by X-Proto-SteamID mask 0x0110000100000000)
#   port mapping= u32 -> u64 via | 0x0110000100000000 (proven by decomp line 194)
#
# Data-flow (verified, unique write):
#   case 768 (identity msg)  -> lpMem+9 (u32)  -> dword_1801E0614   [UNIQUE WRITE]
#   Get_e_Ticket (case 5527) -> sub_180010780(..., (u32)dword_1801E0614, ...)
#   X-Proto-SteamID          = (u32)dword_1801E0614 | 0x0110000100000000
#
# Key decomp references:
#   - line 883:  dword_1801E0614 = *(_DWORD *)((char *)lpMem + 9)   [UNIQUE WRITE, case 768]
#   - line 828:  sub_180010780(..., (u32)dword_1801E0614, ...)      [case 5527]
#   - line 194:  *(_QWORD *)... = (QWORD)(low32) | 0x1100000000000000LL  [X-Proto mask]
#
# Proved invariances (src/user_id_test.cpp):
#   (1) same input steamid64 -> same steamid32 (determinism / round-trip)
#   (2) known identity message (768) -> expected dword value (lpMem+9 read)
#   (3) known manifest -> expected host list (02-manifest-hosts)
#   Run: cmake --build . && ./build/01_userid_test
#
# Conversion helpers (src/steamid_conv.h / steamid_conv.cpp):
#   u32 low32_of(u64 sid64)
#   u64 make_steamid64(u32 sid32)
#   std::string steamid_parse(str)
#   std::string steamid32_to_proto_string(u32)
