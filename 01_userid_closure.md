# 01-userid - closure
01-userid branch'i CLOSED

SteamID conversion port (01-userid CLOSED)

Data-flow (verified via sub_180051810 case 768):
    identity msg (case 768) -> lpMem+9 (u32) -> dword_1801E0614 [UNIQUE WRITE]
    -> sub_180010780 (Get_e_Ticket) reads it as userid in request body
    -> X-Proto-SteamID = low32 | 0x0110000100000000 (sub_1800381E0 line 194)

All 4 closure criteria met:
    source      = identity message, lpMem+9
    raw value   = uint32
    semantic    = SteamID low32
    port mapping= u32 -> u64 via mask (sub_1800381E0 line 194)

01-userid branch: c51ce43
Parent (02-manifest-hosts): f9a293b