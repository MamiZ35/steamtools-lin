# 05-A — Request schema (sub_180010780 + case 5527 caller)
Statüsler: PROVEN / DIFFERENT / UNKNOWN (tahmin EDİLMEZ)
Kaynak: base/sub_180010780_Get_e_Ticket.c (tüm 191 satır),
        base/sub_1800381E0_api_client.c, base/sub_180051810_emulation.c,
        Core_decrypted.bin string dump (offset 1793880-1795276)

## 1) sub_180010780 — request (JSON) oluşturma bölümü [PROVEN]
decomp satır 38-60 (birebir):
  v7 = a5; v31 = a5; v30 = 0; *a3 = 0; *a5 = 0;
  Object = cJSON_CreateObject();
  v9 = Object;
  if (!Object) return 0;
  cJSON_AddNumberToObject(Object, "appid");      // satır 48 -> değer = a1
  cJSON_AddNumberToObject(v9,     "userid");     // satır 49 -> değer = a2
  [satır 50-54: JSON parse / size check buffer]
  sub_180010FE0(lpMem, ..., "/api", 4);          // satır 55 -> URL "/api"
  sub_1800381E0(v32, "Get_e_Ticket", v9, v14);    // satır 59 -> API çağrısı

SONUÇ (PROVEN): reference Get_e_Ticket JSON = EXAKT olarak 2 alan:
  { "appid": <a1>, "userid": <a2> }
  - "type" ALANI YOK (decomp + binary dump + tüm decomp'lar grep'i ile doğrulandı).
  - "name" ALANI YOK (reference sadece appid+userid).
  - cJSON_AddNumber -> value kaydı a1/a2 parametreleri; decompiler eldiği için
    a1=appid, a2=userid (see satır 48-49 ve caller'a uyar).

Binary string dump (Core_decrypted.bin) doğrulama:
  offset 1793880: "appid"   1794780: "userid"  1794800: "Get_e_Ticket"
  Get_e_Ticket civarında (1794000-1796000) NEĞET "type" ve "name" YOKTIR.
  "type" yalnızca GetDepotsKey (180039FE0) comment'inde ve DLC protobuf
  akışında (appids_db.h line 39: type 0) görür -> Get_e_Ticket'te YOKTIR.

## 2) case 5527 çevresinden type / appid / userid kaynağı [PROVEN]
sub_180051810_emulation.c case 5527 (satır 484-920). Data flow:
  [protobuf msg parse] -> v39 = appid (u32)
     (field type 15/8/16 parse -> v39; satır 439-536 civarı decode)
  [appid == 10000 check / v49 flag]
  [e-tick cache lookup] -> (lpMem, FileName) [satır 501-920]
     v48=0, v49=0 default; e-tick cached if field15==1 && v49 set.
  [satır 800-920]:
    if (v48) {
        if (v49) { sub_180010DA0(v39, dword_1801E0614, &String, 0); return; }
        ...e-tick cache hit->...
    } else {   // ilk defa -> sub_180010780 çağrılır (satır 807-813)
        v88 = xmmword_1801E07A0; ... while(*(_DWORD*)v88 != v39) ... (list search)
        if (list match found & no cache) -> e-tick cache miss
            -> Mtx_lock; if cache empty:
        if (!(sub_180010780(
              v39,                        // a1 = appid (u32)
               (unsigned int)dword_1801E0614,  // a2 = SteamID LOW32 (u32)
               &lpMem, FileName, &Size)))
              return;
        ...
        ...
    }
  -> SONRA e-tick binary (FileName) yazılır + protobuf'e e-tick field (26) eklenir
     (satır 943-976: VirtualAlloc+memmove+ 26 field + size varint).

  PROVEN (case 5527 -> sub_180010780):
    appid  = v39 (u32, protobuf'dan decode edilen appid)
    userid = (unsigned int)dword_1801E0614  (identity msg lpMem+9 -> UNIQUE WRITE
                                              -> a2 parametre; PROVEN 01-userid branch)

## 3) "type" kaynağı [PROVEN]
KESİN bulgu: reference Get_e_Ticket JSON'nda "type" ALANI YOKTIR.
  - decomp 191 satırı taranır, yalnızca "appid" + "userid" eklenir.
  - "type" ı string ı Get_e_Ticket yakın bölgesinde YOK (dump).
  - Tüm decomp'ları grep -> "type" ı yalnızca:
      sub_180039FE0.c line 17 (GetDepotsKey comment)
      appids_db.h line 39 (DLC protobuf type 0)
  -> Get_e_Ticket'e AİT type KAYNAĞI YOKTIR.
  (GetDepotsKey/DLC'de type ı farklı bir API call'ı -> 05-A scope dışı,
   GetDepotsKey body'li sub_18004A2C0 + sub_180018350 ile analiz edilecek.)

## 4) REFERENCE vs PORT karşılaştırma (05)
  (reference: sub_180010780 + sub_1800381E0; port: src/eticket.cpp + src/stable_client.cpp)

  REFERENSS              PORT                       STATÜ
  -----------------------------------------------------------
  appid      = a1 (u32,   eticket.cpp body =        PROVEN  (field ı eşleşir;
    caller'da        {"appid":<n>}                 değer ı u32 -> PROVEN)
    sub_180051810
                   src/eticket.cpp line 166-168
                  (v39'dan geliyor)
  userid     = (u32)      body = steamid FULL       DIFFERENT
    low32        (u32 low32)   string (64-bit)   (reference low32,
                   line 185     -> a2             port FULL steamid64)
  type       =          YOK  body = "type" YOK    DIFFERENT (reference
  "name"      =          YOK  body = "name":"..."  PROVEN (reference
                              (line 172-174)     yok -> port EXTRA field)
  headers    = X-Proto-*  stable_client.cpp       PROVEN  (header set ı
    X-Proto-*      =           X-Proto-*         eşleşir)
  encoding   = body       sha256(sig) =          PROVEN  (body'ı raw)
    raw JSON      = body    SHA-256 hex         (X-Proto-Sig:
    (raw)              (line 88)               body ı hash -> ı
                                           sha256_hex == reference)
    X-Proto-Compressed = "0"   -> "0"          PROVEN
    X-Proto-Sig    = SHA-256  sha256_hex(body)  PROVEN
  response   = {"steamid":,  {"e_ticket"/"eTicket"} PROVEN  (parse)
    "e_ticket"}   = {"e_ticket"}/            (hex decode -> ı
    (beta)                 "eTicket"}          binary ı decode PROVEN)
  X-Proto-   = (u32)|      = FULL steamid64     DIFFERENT
  SteamID     0x110000100000000    (line 132)  (reference MASK ile ı low32)
  type       =          YOK  =          YOK    DIFFERENT (reference yok)
-----------------------------------------------------------

  ÖNEMLİ:
  1. type ı (reference Get_e_Ticket) YOKTIR -> port'a "type" EKLEME (PROVEN yok).
  2. "name" ı port'a EKLENİYOR ama reference'ta YOK -> DIFFERENT.
  3. userid ı: reference LOW32, port FULL steamid64 -> DIFFERENT (en kritik).
  4. X-Proto-SteamID: reference (u32|0x110000100000000) MASK, port FULL steamid64
     -> DIFFERENT (mask'ı 0x110000100000000 = 0x0110000100000000 PROVEN,
     binary + decomp + closure.md ile ı).

NOT: 05-A bitişti. 05-B (sub_180039FE0 + sub_18003FC80 function boundary
decomp ile doğrulama) ayrı bir çalışmaymış -> sonraki step.
