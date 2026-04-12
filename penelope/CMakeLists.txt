cmake_minimum_required(VERSION 3.16)
project(padme LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Crystals REQUIRED)
find_package(OpenSSL  REQUIRED)

# ── RPATH for TBB and XKCP shared libraries ───────────────────────────────────
get_target_property(_tbb_loc TBB::tbb IMPORTED_LOCATION_RELEASE)
if(NOT _tbb_loc)
    get_target_property(_tbb_loc TBB::tbb IMPORTED_LOCATION)
endif()
get_filename_component(_tbb_libdir "${_tbb_loc}" DIRECTORY)
set(CMAKE_BUILD_RPATH "${_tbb_libdir}" "/usr/local/lib")

# ── Executable ────────────────────────────────────────────────────────────────
add_executable(padme
    src/main.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/lodepng.cpp
)

target_include_directories(padme PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}   # lodepng.h (at padme root)
    src/                          # encaps_crypto.hpp, bitmap_font.hpp
)

target_compile_options(padme PRIVATE -O2 -Wall -Wextra)

target_link_libraries(padme PRIVATE
    Crystals::crystals
    OpenSSL::Crypto
)

# ── Install ───────────────────────────────────────────────────────────────────
install(TARGETS padme DESTINATION bin)
