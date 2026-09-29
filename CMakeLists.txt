
# SteamCore - Linux port (SteamTools-equivalent core)
cmake_minimum_required(VERSION 3.20)
project(steamtools-lin CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(MSVC)
    add_compile_options(/W4)
else()
    add_compile_options(-Wall -Wextra -fPIC -O2)
endif()

add_library(steamcore SHARED
    src/crypto.cpp
    src/machine_id.cpp
    src/version.cpp
    src/core.cpp
    src/stable_client.cpp
    src/manifest.cpp
    src/beta_client.cpp
    src/appids_db.cpp
    src/eticket.cpp
    src/host_cfg.cpp
)
target_include_directories(steamcore PUBLIC src)

# System libraries
target_link_libraries(steamcore PRIVATE
    -lcurl
    -lcrypto
    -lz
    -lsqlite3
)

# CLI tool
add_executable(core_cli src/main.cpp)
target_link_libraries(core_cli PRIVATE steamcore)
set_target_properties(core_cli PROPERTIES OUTPUT_NAME steamtools-cli)

# Unit test
add_executable(crypto_test src/cryptotest.cpp)
target_link_libraries(crypto_test PRIVATE steamcore)

