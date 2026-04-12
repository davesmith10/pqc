# BLAKE3 + oneTBB Build Notes

## Overview

BLAKE3 is built as a static library (`libblake3.a`) with oneTBB parallelism enabled.
oneTBB is built as a shared library (`libtbb.so.12`) — static oneTBB is explicitly
unsupported upstream (multiple copies of global scheduler state cause problems).

Both are installed to the shared local prefix: `Crystals/local/`

---

## Source locations

| Component | Source                                    |
|-----------|-------------------------------------------|
| oneTBB    | `Crystals/oneTBB/`                        |
| BLAKE3/c  | `Crystals/BLAKE3/c/`                      |

---

## Step 1: Build and install oneTBB

```sh
cmake \
  -S /mnt/c/Users/daves/OneDrive/Desktop/Crystals/oneTBB \
  -B /mnt/c/Users/daves/OneDrive/Desktop/Crystals/oneTBB/build \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX=/mnt/c/Users/daves/OneDrive/Desktop/Crystals/local \
  -DTBB_TEST=OFF \
  -DTBB_EXAMPLES=OFF \
  -DTBBMALLOC_BUILD=OFF \
  -DTBB_STRICT=OFF

cmake --build /mnt/c/Users/daves/OneDrive/Desktop/Crystals/oneTBB/build -j$(nproc)
cmake --install /mnt/c/Users/daves/OneDrive/Desktop/Crystals/oneTBB/build
```

**Result:** `local/lib64/libtbb.so.12.18` (+ `.so.12`, `.so` symlinks)
CMake package config: `local/lib64/cmake/TBB/TBBConfig.cmake`

Options used:
- `TBB_TEST=OFF` — skip test suite (saves significant build time)
- `TBBMALLOC_BUILD=OFF` — skip scalable allocator (not needed for BLAKE3)
- `TBB_STRICT=OFF` — treat warnings as warnings, not errors (avoids noise with GCC 11)

---

## Step 2: Build and install BLAKE3/c

```sh
cmake \
  -S /mnt/c/Users/daves/OneDrive/Desktop/Crystals/BLAKE3/c \
  -B /mnt/c/Users/daves/OneDrive/Desktop/Crystals/BLAKE3/c/build \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX=/mnt/c/Users/daves/OneDrive/Desktop/Crystals/local \
  -DCMAKE_PREFIX_PATH=/mnt/c/Users/daves/OneDrive/Desktop/Crystals/local \
  -DBLAKE3_USE_TBB=ON

cmake --build /mnt/c/Users/daves/OneDrive/Desktop/Crystals/BLAKE3/c/build -j$(nproc)
cmake --install /mnt/c/Users/daves/OneDrive/Desktop/Crystals/BLAKE3/c/build
```

**Result:** `local/lib64/libblake3.a` (static, with TBB as transitive dependency)
CMake package config: `local/lib64/cmake/blake3/blake3-config.cmake`

Key: `CMAKE_PREFIX_PATH` points at `local/` so `find_package(TBB)` finds the just-built oneTBB.
`BLAKE3_USE_TBB=ON` enables `blake3_tbb.cpp` and links `TBB::tbb`.

SIMD acceleration active (confirmed in configure output):
- AMD64 hand-written assembly: SSE2, SSE4.1, AVX2, AVX512

---

## Installed layout (Crystals/local/)

```
local/
  include/
    blake3.h
    oneapi/tbb/          (full TBB headers)
    tbb/                 (compat aliases)
  lib64/
    libblake3.a
    libtbb.so -> libtbb.so.12
    libtbb.so.12 -> libtbb.so.12.18
    libtbb.so.12.18
    cmake/
      TBB/               (TBBConfig.cmake, TBBTargets.cmake, ...)
      blake3/            (blake3-config.cmake, blake3-targets.cmake, ...)
    pkgconfig/
      tbb.pc
      libblake3.pc
```

---

## Using in a downstream CMake project

```cmake
find_package(BLAKE3 REQUIRED)
find_package(TBB    REQUIRED)   # explicit so we can extract the lib dir for RPATH
target_link_libraries(mytarget PRIVATE BLAKE3::blake3 TBB::tbb)
```

Configure with:
```sh
cmake -S . -B build \
  -DCMAKE_PREFIX_PATH=/mnt/c/Users/daves/OneDrive/Desktop/Crystals/local
```

**Runtime:** the final binary loads `libtbb.so.12` at startup.  hybrid's CMakeLists.txt
derives the TBB library directory from the imported target and sets `CMAKE_BUILD_RPATH`
automatically — no `LD_LIBRARY_PATH` required when running from the build tree.

---

## hybrid build command (with BLAKE3 UUID derivation)

```sh
cmake -S pqc/hybrid -B pqc/hybrid/build \
  -DCMAKE_PREFIX_PATH=/mnt/c/Users/daves/OneDrive/Desktop/Crystals/local
cmake --build pqc/hybrid/build -j$(nproc)
```

---

## Why oneTBB must be shared

oneTBB's static build (`BUILD_SHARED_LIBS=OFF`) is explicitly unsupported upstream
(emits a CMake WARNING and is not tested). The reasons:

- The thread pool and task arenas are **process-global singletons** — multiple static
  copies (e.g. from two libraries both statically linking TBB) corrupt each other.
- TBB uses **dynamic library lifecycle hooks** (`constructor`/`destructor` attributes,
  `dlopen`/`dlclose`) for scheduler startup/shutdown.
- **Thread-local storage** for worker threads would collide across copies.

`libblake3.a` is static; the TBB dependency is carried as a transitive link to the shared lib.
