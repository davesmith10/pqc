cmake_minimum_required(VERSION 3.16)
project(obi-wan LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Crystals REQUIRED)
find_package(OpenSSL REQUIRED)

# RPATH: TBB lives in a non-standard path (Crystals/local/).
# TBB::tbb is available transitively after find_package(Crystals) because
# CrystalsConfig.cmake runs find_package(TBB) internally with the baked-in hint.
# /usr/local/lib included unconditionally so libXKCP.so resolves without
# requiring a prior ldconfig run.
get_target_property(_tbb_loc TBB::tbb IMPORTED_LOCATION_RELEASE)
if(NOT _tbb_loc)
    get_target_property(_tbb_loc TBB::tbb IMPORTED_LOCATION)
endif()
get_filename_component(_tbb_libdir "${_tbb_loc}" DIRECTORY)
set(CMAKE_BUILD_RPATH "${_tbb_libdir}" /usr/local/lib)

add_executable(obi-wan src/main.cpp)

target_link_libraries(obi-wan PRIVATE
    Crystals::crystals
    OpenSSL::Crypto
)

target_compile_options(obi-wan PRIVATE -O2 -Wall -Wextra)

install(TARGETS obi-wan DESTINATION bin)
