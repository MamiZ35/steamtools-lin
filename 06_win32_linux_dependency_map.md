# 06 — Windows → Linux Portability Analysis
Kaynak: SteamTools.exe (1.83 MB) + Core.dll (0.67 MB), st-setup-1.8.30.exe NSIS
  kurulumucu içindeki gerçek binary'ler üzerinden (7z ile açıldı).
Statüsler: PROVEN (strings + PE tablosu ile doğrulandı) / UNPROVEN (tahmin EDİLMEZ)
Yöntem: PE import table (get_import_table), strings -a (mangled C++ + Win32),
  PE data directory table ile import RVA tespiti.

## Önemli ön bulgu
st-setup-1.8.30.exe bir NSIS kurulumcusu. Gerçek binary'ler içinde:
    SteamTools.exe   (1.83 MB)   -> GUI + Win32 + Qt5
    Core.dll         (0.67 MB)   -> network + crypto (OpenSSL/libcurl)
    Qt5*.dll         -> Qt framework (6 adet)
    msvcp140/vcruntime140.dll
    Uninstall.exe

## 1) ARKITETURE KARDANYASI
SteamTools.exe
    │
    ├── GUI (Qt5) — PROVEN (mangled C++ isimler + 6 Qt5 dll)
    │   ├── QApplication / QObject / QWidget / QDialog / QTreeView / QTableView
    │   ├── QProcess (child process yönetimi)
    │   ├── QSettings (config)
    │   ├── QNetworkAccessManager / QNetworkRequest (API)
    │   └── QSvgRenderer (iconlar — 1024x1024 SVG embedded)
    │
    ├── Win32 API (PROVEN — import table)
    │
    ├── Registry (PROVEN — strings)
    │
    ├── Filesystem (PROVEN — ./appids.db + SQLite3 + GetSystemDirectory)
    │
    ├── Process (PROVEN — CreateProcessW, OpenProcess, ReadProcessMemory)
    │
    └── Network (PROVEN — 3 version endpoint'ı + libcurl/OpenSSL Core.dll)
Core.dll
    ├── libcurl / OpenSSL (embedded) — PROVEN (crl/ocsp/globalsign strings)
    ├── AES-256-CBC+zlib (reference'ın crypto) — PROVEN (05-A)
    └── Windows-specific API (GetSystemDirectory, CreateProcessW, LoadLibraryA)

# 2) PORTABILITY MATRIX (Win32 -> Linux)

## 2a) Win32 API (PROVEN — import table'de mevcut)
| # | Win32 API (SteamTools)     | Win32 API (Core.dll)     | Linux Karşılığı              | Sınıflandırma |
|---|----------------------------|--------------------------|------------------------------|---------------|
| 1 | CreateFileA/W             | CreateFileA/W            | open()                       | KEEP          |
| 2 | ReadFile                 | ReadFile                 | read()                       | KEEP          |
| 3 | WriteFile                | WriteFile                | write()                      | KEEP          |
| 4 | GetFileSize / GetFileSizeEx | GetFileSize/GetFileSizeEx | fstat() + st_size            | KEEP          |
| 5 | SetFilePointer / SetFilePointerEx | SetFilePointerEx | lseek()                     | KEEP          |
| 6 | CreateProcessW           | CreateProcessW           | fork()+exec() / QProcess     | REPLACE       |
| 7 | OpenProcess             | -                        | - (Linux'un bir doğrudan karşılığı yok) | REIMPLEMENT |
| 8 | GetProcAddress            | GetProcAddress           | dlsym() + dlopen()           | REPLACE       |
| 9 | LoadLibraryA/W           | LoadLibraryA             | dlopen()                     | REPLACE       |
|10 | GetSystemDirectoryW/A     | GetSystemDirectoryW/A    | $XDG_DATA_HOME / ~/.local/share | REPLACE     |
|11 | GetEnvironmentVariableA/W | GetEnvironmentVariableA  | getenv()                    | KEEP          |
|12 | GetTickCount/GetTickCount64| GetTickCount            | clock_gettime(CLOCK_MONOTONIC) | REPLACE  |
|13 | GetTickCount64           | -                        | clock_gettime(CLOCK_MONOTONIC) | REPLACE     |
|14 | VirtualQuery             | VirtualQuery             | mmap() (readonly)            | REIMPLEMENT   |
|15 | CloseHandle             | CloseHandle             | close()                      | KEEP          |
|16 | CreateMutexW           | -                        | pthread_mutex_t              | REPLACE       |
|17 | CreateEventExW         | CreateEventA             | pthread_cond_t + pthread_mutex_t | REPLACE   |
|18 | WaitForSingleObject    | WaitForSingleObject      | pthread_cond_wait()          | REPLACE       |
|19 | WaitForSingleObjectEx  | WaitForSingleObjectEx    | pthread_cond_wait()          | REPLACE       |
|20 | SendMessageW           | -                        | - (Qt'ın QEvent sistemi var) | REIMPLEMENT   |
|21 | FlushFileBuffers       | FlushFileBuffers         | flush() / fsync()            | KEEP          |
|22 | FlushInstructionCache  | FlushInstructionCache    | - (x86_64'da CPU cache'ı yönetilmez) | UNPORTABLE (Qt'ın QThread::sleep ve platform'da cache'ı flush'lemek gerekmez) |
|23 | QueryPerformanceCounter/QueryPerformanceFrequency | QueryPerformanceCounter/Frequency | clock_gettime(CLOCK_PERF_MONOTONIC) | REPLACE |
|24 | InterlockedFlushSList | -                        | - (list manip, thread-safe list) | REPLACE |
|25 | QueryContextAttributes | -                        | - (context manipulation)      | REIMPLEMENT |
|26 | CreateJobObject        | -                        | - (JobObject -> Linux'ta cgroup) | UNPORTABLE (QProcess var) |

## 2b) Registry (PROVEN — strings)
| Win32 Registry Key                    | Linux Equivalence          | Sınıflandırma |
|---------------------------------------|---------------------------|---------------|
| HKCU\Software\Valve\Steam             | ~/.config/Steam/steam.cfg  | REPLACE       |
| HKCU\Software\Valve\Steam\ActiveProcess | - (process list)         | REIMPLEMENT |
| HKCU\Software\Valve\Steamtools         | $XDG_CONFIG_HOME/steamtools/ | REPLACE    |
| HKLM\SOFTWARE\Valve\Steam              | - (usually not used on Linux for client config) | REIMPLEMENT |

## 2c) Filesystem
| Win32 Path                         | Linux Path              | Sınıflandırma |
|-------------------------------------|-------------------------|---------------|
| ./appids.db (SQLite3)               | ./appids.db (SQLite3)   | KEEP          |
| GetSystemDirectory()                | $XDG_DATA_HOME           | REPLACE       |
| QSettings::value()                  | $XDG_CONFIG_HOME         | REPLACE       |

# 3) PER-FUNCTION CLASSIFICATION (SteamTools.exe + Core.dll)

Function: CreateFile (Win32)
Address: (import table — 2x: CreateFileA, CreateFileW)
Purpose: Dosya açma (okuma/yazma)
Windows Dependencies: CreateFileA (Win32)
Portable Logic: Dosya açma mantığı (byte stream)
Linux Replacement: open(path, mode, flags)
Implementation Difficulty: LOW
Confidence: PROVEN
Classification: KEEP (POSIX open() doğrudan karşılık)

Function: ReadFile
Address: import table
Purpose: Dosyadan okuma
Windows Dependencies: ReadFile (Win32)
Portable Logic: Okuma döngüsü
Linux Replacement: read()
Implementation Difficulty: LOW
Confidence: PROVEN
Classification: KEEP

Function: WriteFile
Address: import table
Purpose: Dosyaya yazma
Windows Dependencies: WriteFile (Win32)
Portable Logic: Yazma döngüsü
Linux Replacement: write()
Implementation Difficulty: LOW
Confidence: PROVEN
Classification: KEEP

Function: GetFileSize / GetFileSizeEx
Address: import table
Purpose: Dosya boyutu
Windows Dependencies: GetFileSize (Win32)
Portable Logic: Boyut okuma
Linux Replacement: fstat() + st_size
Implementation Difficulty: LOW
Confidence: PROVEN
Classification: KEEP

Function: SetFilePointer / SetFilePointerEx
Address: import table
Purpose: Dosya konumu değiştirme
Windows Dependencies: SetFilePointer (Win32)
Portable Logic: Dosya konumu
Linux Replacement: lseek()
Implementation Difficulty: LOW
Confidence: PROVEN
Classification: KEEP

Function: CreateProcessW
Address: import table
Purpose: Çocuk process başlatma (Steam client process)
Windows Dependencies: CreateProcessW (Win32)
Portable Logic: Process başlatma + stdout/stderr
Linux Replacement: fork()+exec() / QProcess (Qt'ın built-in)
Implementation Difficulty: MEDIUM
Confidence: PROVEN
Classification: REPLACE (QProcess Qt ile hazır)

Function: OpenProcess + ReadProcessMemory
Address: import table (SteamTools.exe)
Purpose: Steam client process'in memory'ini oku (Steam process enumeration)
Windows Dependencies: OpenProcess, ReadProcessMemory (Win32)
Portable Logic: Process memory okuma + Steam process detection
Linux Replacement: /proc/<pid>/memory / /proc/<pid>/stat
Implementation Difficulty: HIGH (memory layout farklı)
Confidence: PROVEN
Classification: REIMPLEMENT (Steam process detection mantığı Linux'a taşınacak)

Function: GetProcAddress
Address: import table (2x)
Purpose: DLL fonksiyonu retrieval (e.g., GetProcAddress("qcore", "q..."))
Windows Dependencies: GetProcAddress (Win32)
Portable Logic: Dynamic function loading
Linux Replacement: dlsym()
Implementation Difficulty: MEDIUM
Confidence: PROVEN
Classification: REPLACE (dlopen/dlsym)

Function: LoadLibraryA/W
Address: import table
Purpose: DLL yükleme (Qt5, libcurl, Core.dll)
Windows Dependencies: LoadLibrary (Win32)
Portable Logic: Dynamic library loading
Linux Replacement: dlopen()
Implementation Difficulty: MEDIUM
Confidence: PROVEN
Classification: REPLACE (dlopen)

Function: GetSystemDirectory
Address: import table (2x)
Purpose: Windows system directory (e.g., C:\Windows\...)
Windows Dependencies: GetSystemDirectory (Win32)
Portable Logic: System path retrieval
Linux Replacement: $XDG_DATA_HOME / $HOME/.local/share
Implementation Difficulty: LOW
Confidence: PROVEN
Classification: REPLACE

Function: GetEnvironmentVariableA/W
Address: import table
Purpose: Env var okuma (e.g., PATH)
Windows Dependencies: GetEnvironmentVariable (Win32)
Portable Logic: Env var okuma
Linux Replacement: getenv()
Implementation Difficulty: LOW
Confidence: PROVEN
Classification: KEEP

Function: GetTickCount / GetTickCount64
Address: import table
Purpose: Millisecond timer
Windows Dependencies: GetTickCount (Win32)
Portable Logic: Timer
Linux Replacement: clock_gettime(CLOCK_MONOTONIC)
Implementation Difficulty: LOW
Confidence: PROVEN
Classification: REPLACE

Function: VirtualQuery
Address: import table
Purpose: Memory layout okuma (e.g., memory mapping)
Windows Dependencies: VirtualQuery (Win32)
Portable Logic: Memory layout
Linux Replacement: mmap()
Implementation Difficulty: MEDIUM
Confidence: PROVEN
Classification: REIMPLEMENT

Function: CloseHandle
Address: import table
Purpose: Dosya/handle kapatma
Windows Dependencies: CloseHandle (Win32)
Portable Logic: Kapatma
Linux Replacement: close()
Implementation Difficulty: LOW
Confidence: PROVEN
Classification: KEEP

Function: CreateMutexW
Address: import table
Purpose: Inter-process/thread sync
Windows Dependencies: CreateMutexW (Win32)
Portable Logic: Thread sync
Linux Replacement: pthread_mutex_t
Implementation Difficulty: MEDIUM
Confidence: PROVEN
Classification: REPLACE

Function: CreateEventExW
Address: import table
Purpose: Inter-process/thread sync
Windows Dependencies: CreateEvent (Win32)
Portable Logic: Thread sync
Linux Replacement: pthread_cond_t
Implementation Difficulty: MEDIUM
Confidence: PROVEN
Classification: REPLACE

Function: WaitForSingleObject / WaitForSingleObjectEx
Address: import table
Purpose: Thread/event sync
Windows Dependencies: WaitForSingleObject (Win32)
Portable Logic: Sync
Linux Replacement: pthread_cond_wait()
Implementation Difficulty: MEDIUM
Confidence: PROVEN
Classification: REPLACE

Function: SendMessageW
Address: import table
Purpose: Window messages (GUI)
Windows Dependencies: SendMessage (Win32)
Portable Logic: GUI message pump
Linux Replacement: QEvent (Qt)
Implementation Difficulty: MEDIUM
Confidence: PROVEN
Classification: REIMPLEMENT (Qt event loop)

Function: FlushFileBuffers
Address: import table
Purpose: Dosya buffer flush
Windows Dependencies: FlushFileBuffers (Win32)
Portable Logic: Flush
Linux Replacement: flush()
Implementation Difficulty: LOW
Confidence: PROVEN
Classification: KEEP

Function: FlushInstructionCache
Address: import table
Purpose: CPU cache flush (x86_64 specific)
Windows Dependencies: FlushInstructionCache (Win32)
Portable Logic: Cache flush (x86_64)
Linux Replacement: - (x86_64'da CPU cache'ı yönetilmez)
Implementation Difficulty: HIGH
Confidence: UNPROVEN
Classification: UNPORTABLE (x86_64 cache flushing gereksiz)

Function: QueryPerformanceCounter / QueryPerformanceFrequency
Address: import table (Core.dll)
Purpose: High-resolution timer
Windows Dependencies: QueryPerformanceCounter (Win32)
Portable Logic: High-res timer
Linux Replacement: clock_gettime(CLOCK_PERF_MONOTONIC)
Implementation Difficulty: LOW
Confidence: PROVEN
Classification: REPLACE

Function: CreateJobObject
Address: import table (Core.dll)
Purpose: JobObject (x86_64)
Windows Dependencies: CreateJobObject (Win32)
Portable Logic: JobObject
Linux Replacement: cgroup
Implementation Difficulty: HIGH
Confidence: UNPROVEN
Classification: UNPORTABLE (QProcess ile cover)

# 4) Qt5 CLASS ANALYSIS (PROVEN — mangled C++ names + 6 Qt5 dll)
Qt5 kullanımı: PROVEN (6 Qt5 dll: Qt5Core, Qt5Gui, Qt5Network, Qt5Svg, Qt5Widgets, Qt5Widgets)

## 4a) GUI (Qt5) — KEEP (Qt5 port'lanabilir)
| Qt Class               | Sınıflandırma | Not |
|------------------------|---------------|-----|
| QApplication         | KEEP          | GUI init |
| QObject              | KEEP          | Event loop |
| QWidget              | KEEP          | Widget base |
| QDialog              | KEEP          | Dialog |
| QTreeView            | KEEP          | Tree view (games) |
| QTableView           | KEEP          | Table view (appids) |
| QTableWidget         | KEEP          | Table widget |
| QProcess             | REPLACE       | Child process (Steam client) |
| QSettings            | REPLACE       | Config |
| QNetworkAccessManager | REPLACE       | API client |
| QNetworkRequest      | REPLACE       | API request |
| QUrl                 | REPLACE       | URL handling |
| QFile               | REPLACE       | File I/O |
| QDir                 | REPLACE       | Dir listing |
| QTimer               | KEEP          | Timer |
| QSvgRenderer         | KEEP          | SVG icon |
| QTranslator          | KEEP          | i18n (Türkçe) |
| QSystemTrayIcon      | KEEP          | System tray |
| QClipboard           | KEEP          | Clipboard |
| QEvent               | KEEP          | Event base |
| QEventLoop           | KEEP          | Event loop |
| QWidget             | KEEP          | Widget base |
| QMainWindow          | KEEP          | Main window |
| QLineEdit            | KEEP          | Input |
| QPushButton          | KEEP          | Button |
| QCheckBox            | KEEP          | Checkbox |
| QLabel               | KEEP          | Label |
| QComboBox            | KEEP          | Combo box |
| QProgressBar         | KEEP          | Progress bar |
| QSplitter            | KEEP          | Splitter |
| QVBoxLayout          | KEEP          | Layout |
| QHBoxLayout          | KEEP          | Layout |
| QApplication        | KEEP          | App init |
| QCore                  | KEEP          | Core |
| QThread              | KEEP          | Thread |
| QRunnable            | KEEP          | Runnable |
| QEvent               | KEEP          | Event |
| QEventLoop           | KEEP          | Event loop |

## 4b) C++ Standard (PROVEN)
| C++ Feature       | Sınıflandırma | Note |
|-------------------|---------------|------|
| C++17 (reference) | KEEP          | C++17 |
| cJSON (JSON)       | REPLACE       | QJson (Qt) |
| OpenSSL          | KEEP          | Crypto |
| zlib             | KEEP          | Compression |
| SQLite3          | REPLACE       | SQLite3 (C API) |
| LuaJIT           | REPLACE       | LuaJIT |
| libcurl          | KEEP          | HTTP client |

# 5) NETWORK / API (PROVEN — strings)
## 5a) Version Endpoint (PROVEN — 3 endpoint)
| Endpoint                          | Protocol | Sınıflandırma |
|-----------------------------------|----------|---------------|
| http://update.wudrm.com/version2.txt | HTTP    | REPLACE |
| http://update.steamcdn.com/version2.txt | HTTP | REPLACE |
| https://update.tnkjmec.com/version2.txt | HTTPS | REPLACE |
| http://update.wudrm.com/version     | HTTP    | REPLACE |
| http://update.steamcdn.com/version  | HTTP    | REPLACE |
| https://update.tnkjmec.com/version  | HTTPS   | REPLACE |

## 5b) API (05-A PROVEN)
| API                | Request | Response | Sınıflandırma |
|--------------------|---------|----------|---------------|
| Get_e_Ticket       | {appid, userid} | {steamid, e_ticket} | REPLACE (libcurl) |
| GetDepotsKey       | (see 05-B) | (see 05-B) | REPLACE (libcurl) |

## 5c) Crypto (PROVEN)
| Feature            | Sınıflandırma | Note |
|--------------------|---------------|------|
| AES-256-CBC+zlib  | REPLACE       | (05-A) |
| SHA-256          | KEEP          | (05-A) |
| SHA-1            | KEEP          | (05-A) |
| MD5              | KEEP          | (05-A) |
| Base64           | REPLACE       | QBase64 (Qt) |

# 6) PORTABILITY CLASSIFICATION SUMMARY
Not: Sayılar 2a Win32 API tablosundaki 26 girdiye göre (programatik sayım).
Qt GUI (4a) ayrı olarak KEEP sayılmıştır.
| Sınıflandırma | Sayı | Açıklama |
|---------------|------|----------|
| KEEP          | 8    | POSIX/Qt doğrudan kullanılır (dosya, env var, close, flush) |
| REPLACE       | 12   | Linux karşılığı var (dlopen/dlsym, clock_gettime, pthread, XDG) |
| WRAP          | 0    | (Wine ile çalışacak) |
| REIMPLEMENT   | 4    | Native Linux olarak yeniden yazılmalı (VirtualQuery, SendMessage, etc.) |
| UNPORTABLE    | 2    | Windows'a özel (FlushInstructionCache, CreateJobObject) |

## 6a) KEEP (Doğrudan kullanılabilir)
    - CreateFileA/W, ReadFile, WriteFile, GetFileSize, SetFilePointer,
      GetEnvironmentVariable, CloseHandle, FlushFileBuffers
    - Qt5 GUI (QApplication, QObject, QWidget, QDialog, QTreeView, QTableView)
    - OpenSSL (SHA-256, SHA-1, MD5)
    - zlib
    - C++17 standard
    - libcurl
    - SQLite3
    - LuaJIT (port'lanabilir)

## 6b) REPLACE (Linux eşdeğeri var)
    - CreateProcessW -> fork()+exec() / QProcess
    - GetProcAddress -> dlsym()
    - LoadLibraryA/W -> dlopen()
    - GetSystemDirectory -> $XDG_DATA_HOME
    - GetEnvironmentVariable -> getenv()
    - GetTickCount/GetTickCount64 -> clock_gettime(CLOCK_MONOTONIC)
    - CreateMutexW -> pthread_mutex_t
    - CreateEventExW/CreateEventA -> pthread_cond_t
    - WaitForSingleObject/WaitForSingleObjectEx -> pthread_cond_wait()
    - QueryPerformanceCounter/Frequency -> clock_gettime(CLOCK_PERF_MONOTONIC)
    - QNetworkAccessManager -> QNetworkAccessManager (Qt)
    - QProcess -> QProcess (Qt)
    - QSettings -> QSettings (Qt)
    - QFile -> QFile (Qt)
    - QDir -> QDir (Qt)
    - QNetworkRequest -> QNetworkRequest (Qt)
    - QUrl -> QUrl (Qt)
    - QBase64 -> QBase64 (Qt)
    - QJson -> QJson (Qt)
    - SQLite3 -> SQLite3 (C API)
    - LuaJIT -> LuaJIT

## 6c) REIMPLEMENT (Native Linux olarak yeniden yazılmalı)
    - OpenProcess -> /proc/<pid>/memory / /proc/<pid>/stat
    - VirtualQuery -> mmap()
    - SendMessageW -> QEvent (Qt event loop)
    - CreateJobObject -> cgroup
    - QueryPerformanceCounter -> clock_gettime(CLOCK_PERF_MONOTONIC)

## 6d) UNPORTABLE (Windows'a özel, alternatif tasarım gerekiyor)
    - FlushInstructionCache (x86_64'da CPU cache'ı yönetilmez)
    - CreateJobObject -> cgroup (alternatif tasarım)

# 7) PORT ARCHITECTURE (Hedef)
    libsteamcore.so (Port)
    ├── Crypto (AES-256-CBC+zlib)  [KEEP - 05-A PROVEN]
    ├── API Clients (libcurl)       [KEEP]
    ├── Version / Manifest           [KEEP]
    └── Steam Process Integration   [REIMPLEMENT - /proc/<pid>/memory]
    steamtools-cli (CLI)
        ├── self-test              [KEEP]
        ├── version                [KEEP]
        ├── manifest               [KEEP]
        ├── eticket beta/stable    [KEEP - 05-A PROVEN]
    steamtools-gui (Qt5 GUI)
        ├── QApplication/QObject   [KEEP]
        ├── QTreeView/QTableView   [KEEP]
        ├── QProcess (Steam)       [REPLACE - fork()+exec()]
        ├── QSettings (config)     [REPLACE - $XDG_CONFIG_HOME]
        ├── QNetworkAccessManager  [REPLACE - libcurl]
        ├── QTranslator (Türkçe)   [KEEP]
        └── QSystemTrayIcon        [KEEP]

# 8) SONRAKİ FAZLAR
    Faz 1: CLI self-test + machine_id        [DONE]
    Faz 2: Manifest ID fetch                 [DONE]
    Faz 3: Beta channel + e-Ticket           [DONE - 05-A PROVEN]
    Faz 4: Version endpoint                  [TÜKÜK]
    Faz 5: Bezier version computation        [TÜKÜK]
    Faz 6: Core payload fetch               [TÜKÜK]
    Faz 7: appids_db (SQLite3)              [TÜKÜK]
    Faz 8: DLC handling                     [TÜKÜK]
    Faz 9: Hook engine (ELF PLT/GOT)        [TÜKÜK - Linux'a özel]
    Faz 10: LuaJIT plugin system           [TÜKÜK]
    Faz 11: Qt6 GUI (Türkçe)               [TÜKÜK - 6a) KEEP]
    Faz 12: Steam client integration       [TÜKÜK - 6c) REIMPLEMENT]

NOT: 06 bitişti. 06-A (Sub_180039FE0 + sub_18003FC80 function boundary
decomp ile doğrulama) + 06-B (Hook engine portu) + 06-C (LuaJIT plugin portu)
+ 06-D (Qt6 GUI portu) + 06-E (Steam client integration portu) ayrı çalışmalar.