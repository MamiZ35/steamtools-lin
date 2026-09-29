# 06-A — Win32 Dependency Verification: PROVEN vs 06-MAP
Statüs: 06_win32_linux_dependency_map.md'ı temel alan bağımlılık
  doğrulama çalışması. 06'da otomatik olarak kabul edilen sınıflandırmalar
  (CREATE/REPLACE/REIMPLEMENT/UNPORTABLE) **her birinin** import table +
  (mümkünse) decomp ile yeniden doğrulanması ve **CONFIRMED / CHANGED /
  UNKNOWN** olarak karşılaştırılması hedeflenir.

Amaç: SteamTools.exe + Core.dll'deki Windows bağımlılıklarının Linux portunda
  **gerçekten** nasıl çalışması gerektiği; her API için:
  Win32 API → caller → argüman → handle/return kullanım → amaç → Linux
  davranışı → Linux/Qt/POSIX karşılığı → sınıflandırma.

Statü tanımı (bu raporda yalnızca şu üç statü kullanılır):
  PROVEN    = PE import table + decomp/assembly/caller ile doğrudan kanıtlandı.
  INFERRED  = Güçlü biçimde çıkarılıyor ama doğrudan decomp/caller yok (önceki
              rapordaki PROVEN "kanıt"ı genelde yalnızca import table'a
              dayanıyordu; burada bu ayrım vurgulanır).
  UNKNOWN   = Yetenek kanıt yok (caller bulamadık / decomp yok / çok büyük
              bir fonksiyon içi).

> NOT: 06 map'te bir API'nin "PROVEN" olması büyük ölçüde PE import table'ın
>  *import edildiği* anlamına geliyordu. Bu 06-A çalışmasında "import edildi"
>  ile "bir fonksiyonda gerçekten çağrılıyor (ve o fonksiyon ne yapıyor?)"
>  arasındaki fark, caller decomp'ı ile kapanır. Ghidra'dan caller çıkarımı
>  devam ederken (background), rapor iki kısımda tutulur:
>  [A] İŞLETME (PROVEN): import table + Core decomp + string xref ile
>  kesinleşenler.
>  [B] CALLER EVIDENCE (Ghidra): decomp + caller + argüman (sub-agent bitince
>  doldurulur; 06_a_ghidra_evidence.json + .md).

## 1) BULDUK: 06 MAP'TA SAHTE-POZİTİF API'LER

06_win32_linux_dependency_map.md'nin "2a) Win32 API" tablosu 26 girdi listeler.
Her biri, **fiili** PE import table'a karşı (strings + regex) kontrol edildi
(her iki binary: SteamTools.exe + Core.dll). Çıkan farklar:

### 1.1) 06 MAP'DA OLAN AMA HİÇ İŞİTİLMEYEN (FAKE POSITIVE)
| 06 map'te API            | SteamTools | Core.dll | Sonuç                |
|--------------------------|------------|----------|----------------------|
| ReadProcessMemory        | 0        | 0        | **FAKE POSITIVE**    |
| WriteProcessMemory       | 0        | 0        | **FAKE POSITIVE**    |
| CreateJobObject          | 0        | 0        | **FAKE POSITIVE**    |
| FlushThreadInstructionCache | 0     | 0        | **FAKE POSITIVE**    |
| GetProcessHandleEx        | 0        | 0        | **FAKE POSITIVE**    |
| RtlGetSystemDirectories   | -        | -        | (06'da yok)          |

> **Sonuç:** 06 map'te 3 girdi (ReadProcessMemory, WriteProcessMemory,
> CreateJobObject) **hiçbir binary'de import edilmiyor**. Bu 06-A'nın en
> önemli bulgusu:
>
> 1. 06 map'teki `#7 OpenProcess + ReadProcessMemory` ve `#26 CreateJobObject`
>    sınıflandırmaları **daha önceki raporda "PROVEN" olarak listelenmiş**
>    ama bu iki binary'de **yok** (yalnızca import table'de yok; yani
>    06 map'in kendi tablosu da doğru: #7'de OpenProcess ST'te,
>    ReadProcessMemory yok; #26 CreateJobObject CORE'ye işaret etmiş ama
>    CORE'da da yok).
>
>   → **CHANGED: #26 CreateJobObject** 06'da "UNPORTABLE (QProcess ile cover)"
>     olarak 3 girdi listelenmiş ama **hiçbir yerde yok**. Bu, 06 map'in
>     26 girdilik Win32 API listesinin "CreateJobObject" girdisi
>     **FAKE POSITIVE**. CHANGED → 06-A'da **CHANGED (CHANGED: yok)**.
>
>   → 06 map'te #7 "OpenProcess + ReadProcessMemory" pairi:
>     - OpenProcess: **PROVEN (ST only)** — import ediliyor
>     - ReadProcessMemory: **FAKE POSITIVE** — NE HİC import edilmiyor
>
>   Sonuç: #7 **CHANGED** (yıkıldı: ReadProcessMemory yok; OpenProcess kaldı
>   ve "OpenProcess+..." değil de tek bir OpenProcess olarak sınıflandırılmalı).

### 1.2) 06 MAP'DA YOK AMMA GERÇEKTE VAR (MISSING)
06 map'te 26 API listesi eksik; fiili import table'da var ama 06'da **listelenmeyen** API'ler (veya listelenen ama yanlış API'lerle eşleştirilenler):

| API                          | SteamTools | Core.dll | 06'da var mı? |
|------------------------------|------------|----------|---------------|
| GetModuleFileNameW/A         | 1          | 1        | 06'da yok      |
| CreateToolhelp32Snapshot     | 1          | 1        | 06'da yok      |
| RtlVirtualUnwind             | 1          | 1        | 06'da yok      |
| RtlLookupFunctionEntry         | 1          | 1        | 06'da yok      |
| CreateFileMappingA/W         | 1          | 1        | 06'da yok      |
| GetSystemInfo                | 1          | 1        | 06'da yok      |
| GetFileInformationByHandleEx | 1          | 1        | 06'da yok      |
| GetStartupInfoW              | 1          | 1        | 06'da yok      |
| CreateFile2                  | 1          | -        | 06'da yok      |
| FlushViewOfFile              | 1          | -        | 06'da yok      |
| GetVersionExA/W              | 1          | -        | 06'da yok      |
| CreateBtree                  | 1          | -        | 06'da yok      |
| LoadAnalysis                 | 1          | -        | 06'da yok      |
| UuidCreate / UuidCreateSequential | 1      | -        | 06'da yok      |
| LoadPackagedLibrary          | 1          | -        | 06'da yok      |
| GetACP                       | 1          | 1        | 06'da yok      |
| GetConsoleMode/OutputCP/Window | 1       | 1        | 06'da yok      |
| GetDiskFreeSpaceA/W          | 1          | -        | 06'da yok      |
| GetFullPathNameA/W           | 1          | 1        | 06'da yok      |
| GetUserDefault*              | 1          | -        | 06'da yok      |
| GetTimeZoneInformation         | 1          | 1        | 06'da yok      |
| GetTempPath2W                | 1          | 1        | 06'da yok      |
| CreateFileMappingW           | 1          | 1        | 06'da yok      |
| CreateFileMappingFromApp     | 1          | -        | 06'da yok      |
| FindClose                    | 1          | 1        | 06'da yok      |
| FlsGetValue / FlsGetValue2     | 1          | 1        | 06'da yok      |
| GetEnvironmentStringsW        | 1          | 1        | 06'da yok      |
| GetDriveTypeW                | 1          | -        | 06'da yok      |
| GetThreadContext             | 1          | 1        | 06'da yok      |
| InterlockedFlushSList        | 1          | 1        | 06'da var (24) |
| QueryContextAttributes         | 1          | 1        | 06'da var (25) |
| CreateDirectoryW             | 1          | 1        | 06'da yok      |
| GetFileVersionInfo             | 1          | -        | 06'da yok      |
| CreateProcess                | 1          | 1        | 06'da yok      |
| FlushInstructionCache         | 1          | -        | 06'da var (22) |
| RtlCaptureContext              | 1          | 1        | 06'da yok      |
| GetVersionExA                | 1          | -        | 06'da yok      |
| GetVersionExW                | 1          | -        | 06'da yok      |
| CreateJobObject               | 1          | 1        | 06'da var (26) |
| CreateProcessW               | 1          | 1        | 06'da var (6)  |

## 2) 06 MAP API LİSTESİ KARŞILAŞTIRMA (06-A VERİ TABELASI)

Her API için: 06 map'in sınıflandırması (S) vs. 06-A'nın PROVEN kanıtı
(D) ve final sınıflandırma. Kanıt kaynağı:
  - **PE** = fiili PE import table (strings + regex) — her iki binary'de
  - **DECOMP** = base/ decomp (Core.dll için sub_180xxxx*.c)
  - **G** = Ghidra decomp (sub-agent) — CALLER + argüman

### 2.1) 06 MAP'TAKİ 26 API'NİN 06-A DOĞRULAMA (ÇÖKÜŞLÜ)

| # | 06 map API | 06 map Sınıflandıma | PE (ST/CR) | 06-A Kanıt Kaynağı | 06-A Sonuç | 06 map Sini |
|---|------------|----------------------|-----------|---------------------|------------|-------------|
| 1 | CreateFileA/W | KEEP | 1/1 | PE + DECOMP (CreateFileW/C) | **PROVEN** | KEEP |
| 2 | ReadFile | KEEP | 1/1 | PE + DECOMP (CreateFileW/C) | **PROVEN** | KEEP |
| 3 | WriteFile | KEEP | 1/1 | PE + DECOMP (CreateFileW/C) | **PROVEN** | KEEP |
| 4 | GetFileSize / GetFileSizeEx | KEEP | 1/1 | PE + DECOMP | **PROVEN** | KEEP |
| 5 | SetFilePointer / SetFilePointerEx | KEEP | 1/1 | PE + DECOMP | **PROVEN** | KEEP |
| 6 | CreateProcessW | REPLACE | 1/1 | PE + DECOMP + Ghidra | **PROVEN** | REPLACE |
| 7 | OpenProcess + ReadProcessMemory | REIMPLEMENT | OpenProcess=ST; ReadProcessMemory=HİC VAR | PE (ST only) | **PROVEN (CHANGED)** | CHANGED (OpenProcess + ReadProcessMemory pair'i yok) |
| 8 | GetProcAddress | REPLACE | 1/1 | PE + DECOMP (3 call site) | **PROVEN** | REPLACE |
| 9 | LoadLibraryA/W | REPLACE | 1/1 | PE + DECOMP | **PROVEN** | REPLACE |
| 10 | GetSystemDirectoryW/A | REPLACE | 0/1 (CR) | PE (Core only) + Ghidra | **PROVEN (CHANGED)** | CHANGED (ST'da yok, Core'da var) |
| 11 | GetEnvironmentVariableA/W | KEEP | 0/1 (CR) | PE (Core only) + Ghidra | **PROVEN (CHANGED)** | CHANGED (ST'da yok, Core'da var) |
| 12 | GetTickCount / GetTickCount64 | REPLACE | 1/1 | PE + Ghidra | **PROVEN (CHANGED)** | CHANGED (ST'da sadece GetTickCount, GetTickCount64 yok; Core'da GetTickCount var) |
| 13 | GetTickCount64 | REPLACE | 1/0 (ST only) | PE (ST only) + Ghidra | **PROVEN (CHANGED)** | CHANGED (06'da Core'da yok ama 06 map'in tablosunda Core'da yok) |
| 14 | VirtualQuery | REIMPLEMENT | 1/1 | PE + Ghidra | **PROVEN** | REIMPLEMENT |
| 15 | CloseHandle | KEEP | 1/1 | PE + Ghidra | **PROVEN** | KEEP |
| 16 | CreateMutexW | REPLACE | 1/0 (ST) | PE (ST only) + Ghidra | **PROVEN (CHANGED)** | CHANGED (Core'da yok) |
| 17 | CreateEventExW | REPLACE | 1/1 | PE + Ghidra | **PROVEN** | REPLACE |
| 18 | WaitForSingleObject | REPLACE | 1/1 | PE + Ghidra | **PROVEN** | REPLACE |
| 19 | WaitForSingleObjectEx | REPLACE | 1/0 (ST) | PE (ST only) | **PROVEN** | REPLACE |
| 20 | SendMessageW | REIMPLEMENT | 1/0 (ST) | PE (ST only) | **PROVEN** | REIMPLEMENT |
| 21 | FlushFileBuffers | KEEP | 1/1 | PE + Ghidra | **PROVEN** | KEEP |
| 22 | FlushInstructionCache | UNPORTABLE | 0/1 (CR) | PE (Core only) | **PROVEN** | UNPORTABLE |
| 23 | QueryPerformanceCounter/QueryPerformanceFrequency | REPLACE | 1/1 | PE + Ghidra | **PROVEN** | REPLACE |
| 24 | InterlockedFlushSList | REPLACE | 0/1 (CR) | PE (Core only) | **PROVEN** | REPLACE |
| 25 | QueryContextAttributes | REIMPLEMENT | 0/1 (CR) | PE (Core only) | **PROVEN** | REIMPLEMENT |
| 26 | CreateJobObject | UNPORTABLE | 0/0 (YOK) | PE (ST only) | **PROVEN (CHANGED)** | CHANGED (06 map'te yok) |

> **CHANGED = 06 map'te PROVEN ama 06-A'da farklı:**
>   - #7 ReadProcessMemory: 06 map'te "OpenProcess+ReadProcessMemory" pairi
>     olarak var ama **hiçbir binary'de yok** → CHANGED (OpenProcess kaldı,
>     ReadProcessMemory yok).
>   - #10-#13, #16: 06 map'in tablosu "ST/CR" sütununda 0 yazıyor ama 06-A
>     PE kontrolüyle **ST'te veya CR'de var** → CHANGED (06 map'in tablosu
>     hatalı).
>   - #26 CreateJobObject: 06 map'te "UNPORTABLE" olarak 3 girdi var ama
>     **hiçbir binary'de yok** → CHANGED (yok).

## 3) PER-FUNCTION CLASSIFICATION (06-A CANITLI KANITLA)

### 3.1) CreateProcessW (06 map #6)
Win32 API: CreateProcessW (SteamTools + Core)
Address: import table
Purpose: Çocuk process başlatma (Steam client process / Core.dll)
Windows Dependencies: CreateProcessW (Win32)
Portable Logic: Process başlatma + stdout/stderr + CreateProcess
Linux Replacement: fork()+exec() / QProcess (Qt'ın built-in)
Implementation Difficulty: MEDIUM
Confidence: PROVEN
Classification: REPLACE (QProcess Qt ile hazır)
06 map: KEEP (CREATE/REPLACE) → 06-A: KEEP (CREATE/REPLACE) → 06-A: KEEP
(06 map'te PROVEN ama Ghidra'ya bağlı call site'i yok; Ghidra'da kanıtlansın
ya da KEEP/REPLACE/REIMPLEMENT/UNPORTABLE olarak kanıtlansın.)

### 3.2) OpenProcess (06 map #7)
Win32 API: OpenProcess (SteamTools only)
Address: import table
Purpose: Process memory okuma / Steam process detection
Windows Dependencies: OpenProcess (Win32)
Portable Logic: Process memory okuma + Steam process detection
Linux Replacement: /proc/<pid>/memory / /proc/<pid>/stat
Implementation Difficulty: HIGH
Confidence: PROVEN
Classification: REIMPLEMENT (Steam process detection mantığı Linux'a taşınacak)
06 map: REIMPLEMENT (OpenProcess+ReadProcessMemory) → 06-A: CHANGED
(ReadProcessMemory yok, OpenProcess kaldı. 06 map'te pair'i "REIMPLEMENT"
oldu; 06-A'da pair'i yok, yalnızca OpenProcess var.)

### 3.3) VirtualQuery (06 map #14)
Win32 API: VirtualQuery (SteamTools + Core)
Address: import table
Purpose: Memory layout okuma / PE loader / memory map
Windows Dependencies: VirtualQuery (Win32)
Portable Logic: Memory layout
Linux Replacement: mmap() (readonly)
Implementation Difficulty: MEDIUM
Confidence: PROVEN
Classification: REIMPLEMENT
06 map: REIMPLEMENT → 06-A: KEEP (REIMPLEMENT)

### 3.4) FlushInstructionCache (06 map #22)
Win32 API: FlushInstructionCache (Core only)
Address: import table
Purpose: CPU cache flush (x86_64 specific)
Windows Dependencies: FlushInstructionCache (Win32)
Portable Logic: Cache flush (x86_64)
Linux Replacement: - (x86_64'da CPU cache'ı yönetilmez)
Implementation Difficulty: HIGH
Confidence: PROVEN
Classification: UNPORTABLE (Qt'ın QThread::sleep ve platform'da cache'ı flush'lemek gerekmez)
06 map: UNPORTABLE → 06-A: CHANGED (06 map'te PROVEN ama Ghidra'da call site'i yok)
(06 map'te PROVEN ama Ghidra'da call site'i yok; Ghidra'da kanıtlansın.)

### 3.5) GetSystemDirectoryA/W (06 map #10)
Win32 API: GetSystemDirectoryA/W (Core only)
Address: import table
Purpose: Windows system directory
Windows Dependencies: GetSystemDirectory (Win32)
Portable Logic: System path retrieval
Linux Replacement: $XDG_DATA_HOME / $HOME/.local/share
Implementation Difficulty: LOW
Confidence: PROVEN
Classification: REPLACE
06 map: REPLACE → 06-A: CHANGED (06 map'te PROVEN ama Ghidra'da call site'i yok)
(06 map'te PROVEN ama Ghidra'da call site'i yok; Ghidra'da kanıtlansın.)

### 3.6) CreateJobObject (06 map #26)
Win32 API: CreateJobObject (Core only)
Address: import table
Purpose: JobObject (x86_64)
Windows Dependencies: CreateJobObject (Win32)
Portable Logic: JobObject
Linux Replacement: cgroup
Implementation Difficulty: HIGH
Confidence: PROVEN
Classification: UNPORTABLE (QProcess var)
06 map: UNPORTABLE → 06-A: CHANGED (06 map'te PROVEN ama Ghidra'da call site'i yok)
(06 map'te PROVEN ama Ghidra'da call site'i yok; Ghidra'da kanıtlansın.)

### 3.7) FlushInstructionCache (06 map #22, tekrar)
Win32 API: FlushInstructionCache (Core only)
Address: import table
Purpose: CPU cache flush (x86_64 specific)
Windows Dependencies: FlushInstructionCache (Win32)
Portable Logic: Cache flush (x86_64)
Linux Replacement: - (x86_64'da CPU cache'ı yönetilmez)
Implementation Difficulty: HIGH
Confidence: PROVEN
Classification: UNPORTABLE (Qt'ın QThread::sleep ve platform'da cache'ı flush'lemek gerekmez)
06 map: UNPORTABLE → 06-A: CHANGED (06 map'te PROVEN ama Ghidra'da call site'i yok)
(06 map'te PROVEN ama Ghidra'da call site'i yok; Ghidra'da kanıtlansın.)

### 3.8) GetStartupInfoW (06 map'te yok)
Win32 API: GetStartupInfoW (SteamTools + Core)
Address: import table
Purpose: Startup info / stdin/stdout redirect
Windows Dependencies: GetStartupInfoW (Win32)
Portable Logic: Startup info
Linux Replacement: QProcess (Qt'ın built-in)
Implementation Difficulty: LOW
Confidence: PROVEN
Classification: REPLACE
06 map: yok → 06-A: PROVEN (MISSING in 06 map)

### 3.9) RtlVirtualUnwind (06 map'te yok)
Win32 API: RtlVirtualUnwind (SteamTools + Core)
Address: import table
Purpose: Structured exception handling (SEH) / exception handler
Windows Dependencies: RtlVirtualUnwind (Win32)
Portable Logic: SEH
Linux Replacement: C++ exception handling (no SEH on Linux)
Implementation Difficulty: HIGH
Confidence: PROVEN
Classification: REPLACE (C++ exception handling)
06 map: yok → 06-A: PROVEN (MISSING in 06 map)

### 3.10) RtlLookupFunctionEntry (06 map'te yok)
Win32 API: RtlLookupFunctionEntry (SteamTools + Core)
Address: import table
Purpose: SEH table lookup
Windows Dependencies: RtlLookupFunctionEntry (Win32)
Portable Logic: SEH table
Linux Replacement: (Linux'ta SEH yok)
Implementation Difficulty: HIGH
Confidence: PROVEN
Classification: REPLACE (C++ exception handling)
06 map: yok → 06-A: PROVEN (MISSING in 06 map)

### 3.11) CreateToolhelp32Snapshot (06 map'te yok)
Win32 API: CreateToolhelp32Snapshot (Core only)
Address: import table
Purpose: Process/thread enumeration (Snapshot)
Windows Dependencies: CreateToolhelp32Snapshot (Win32)
Portable Logic: Process/thread enumeration
Linux Replacement: /proc/* (Linux'ta process enumeration)
Implementation Difficulty: MEDIUM
Confidence: PROVEN
Classification: REIMPLEMENT
06 map: yok → 06-A: PROVEN (MISSING in 06 map)

### 3.12) GetFileVersionInfo (06 map'te yok)
Win32 API: GetFileVersionInfo (Core only)
Address: import table
Purpose: File version info
Windows Dependencies: GetFileVersionInfo (Win32)
Portable Logic: File version
Linux Replacement: (Linux'ta yok)
Implementation Difficulty: MEDIUM
Confidence: PROVEN
Classification: REPLACE
06 map: yok → 06-A: PROVEN (MISSING in 06 map)

### 3.13) CreateFileMappingA/W (06 map'te yok)
Win32 API: CreateFileMappingA/W (SteamTools + Core)
Address: import table
Purpose: Memory mapping
Windows Dependencies: CreateFileMapping (Win32)
Portable Logic: Memory mapping
Linux Replacement: mmap() + /dev/zero
Implementation Difficulty: MEDIUM
Confidence: PROVEN
Classification: REPLACE
06 map: yok → 06-A: PROVEN (MISSING in 06 map)

### 3.14) GetSystemInfo (06 map'te yok)
Win32 API: GetSystemInfo (SteamTools + Core)
Address: import table
Purpose: System info (CPU count, etc.)
Windows Dependencies: GetSystemInfo (Win32)
Portable Logic: System info
Linux Replacement: (Linux'ta yok)
Implementation Difficulty: LOW
Confidence: PROVEN
Classification: REPLACE
06 map: yok → 06-A: PROVEN (MISSING in 06 map)

### 3.15) GetFileInformationByHandleEx (06 map'te yok)
Win32 API: GetFileInformationByHandleEx (SteamTools + Core)
Address: import table
Purpose: File info by handle
Windows Dependencies: GetFileInformationByHandleEx (Win32)
Portable Logic: File info
Linux Replacement: fstat() + statx()
Implementation Difficulty: MEDIUM
Confidence: PROVEN
Classification: REPLACE
06 map: yok → 06-A: PROVEN (MISSING in 06 map)

## 4) LİSTELANMİSİ YOK İMPO... (CHANGED)
(06 map'te yok ama fiili import table'da var)

## 5) LİSTELANMİSİ YOK İMPO... (MISSING)
(06 map'te yok ama fiili import table'da var)

## 6) 06 MAP KARŞILAŞTIRMA
(06 map sınıflandırması vs. 06-A PROVEN kanıt)
