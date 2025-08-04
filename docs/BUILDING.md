# Building libnostr-c

## Prerequisites

### Required Dependencies
- **CMake** 3.16 or higher
- **C99-compatible compiler** (GCC, Clang, MSVC)
- **OpenSSL** development libraries
- **secp256k1** with schnorr support

### Optional Dependencies  
- **libcjson** - Enables enhanced JSON handling (recommended)
- **libwebsockets** - Enables relay communication (recommended)
- **noscrypt** - Enables NIP-44 encryption and advanced features

## Dependency Installation

### Ubuntu/Debian

```bash
# Install build tools
sudo apt update
sudo apt install -y build-essential cmake git

# Install required dependencies
sudo apt install -y libssl-dev

# Install secp256k1 with schnorr support
git clone https://github.com/bitcoin-core/secp256k1.git
cd secp256k1
./autogen.sh
./configure --enable-module-schnorrsig --enable-module-extrakeys
make && sudo make install && sudo ldconfig
cd ..

# Install optional dependencies
sudo apt install -y libcjson-dev libwebsockets-dev

# Install noscrypt (for NIP-44 support)
git clone https://github.com/VnUgE/noscrypt.git
cd noscrypt
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
sudo cmake --install build
cd ..
```

### macOS

```bash
# Install via Homebrew
brew install cmake git openssl

# Install secp256k1
brew install secp256k1

# Install optional dependencies  
brew install cjson libwebsockets

# Install noscrypt (manual build required)
git clone https://github.com/VnUgE/noscrypt.git
cd noscrypt
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
sudo cmake --install build
cd ..
```

### Windows

```powershell
# Install via vcpkg (recommended)
git clone https://github.com/Microsoft/vcpkg.git
cd vcpkg
.\bootstrap-vcpkg.bat

# Install dependencies
.\vcpkg install openssl --triplet x64-windows
.\vcpkg install secp256k1 --triplet x64-windows
.\vcpkg install cjson --triplet x64-windows
.\vcpkg install libwebsockets --triplet x64-windows

# For noscrypt, manual build from source required
# See: https://github.com/VnUgE/noscrypt
```

## Build Instructions

### Standard Build  

```bash
git clone https://github.com/privkeyio/libnostr-c.git
cd libnostr-c
mkdir build && cd build
cmake ..
make -j$(nproc)
```

### Feature-Enabled Build

Enable specific features:

```bash
# Build with all NIPs enabled (requires noscrypt)
cmake .. -DNOSTR_FEATURE_ALL_NIPS=ON

# Build with specific advanced features
cmake .. \
  -DNOSTR_FEATURE_NIP44=ON \
  -DNOSTR_FEATURE_NIP17=ON \
  -DNOSTR_FEATURE_NIP59=ON

# Build without threading (for embedded/single-threaded use)
cmake .. -DNOSTR_FEATURE_THREADING=OFF
```

### Windows Build

```powershell
# Using vcpkg toolchain
cmake .. -DCMAKE_TOOLCHAIN_FILE=C:\path\to\vcpkg\scripts\buildsystems\vcpkg.cmake
cmake --build . --config Release
```

## Troubleshooting

### Missing Dependencies

**Error: `fatal error: noscrypt/noscrypt.h: No such file or directory`**
- noscrypt headers not found
- Install noscrypt from source (see dependency installation above)
- Ensure noscrypt is installed to `/usr/local` or set `NOSCRYPT_DIR` environment variable

**Error: `LINK : fatal error LNK1181: cannot open input file 'cjson.lib'`**
- Missing cJSON on Windows
- Install via vcpkg: `vcpkg install cjson --triplet x64-windows`
- Or disable JSON features: `cmake .. -DNOSTR_FEATURE_JSON_ENHANCED=OFF`

### secp256k1 Version Conflicts

**Error: `undefined reference to secp256k1_schnorrsig_sign32`**
- Older secp256k1 version without schnorr support
- Solution: Install secp256k1 v0.5.0+ with schnorr module enabled (see dependency installation above)

### Threading Issues

**Error: `undefined reference to pthread_*` on Windows**
- Threading code compiled without proper Windows support
- Solution: Use MSVC with Windows threading or disable threading:
```bash
cmake .. -DNOSTR_FEATURE_THREADING=OFF
```

### Environment Variables

For custom library locations:
```bash
# Set noscrypt location
export NOSCRYPT_DIR=/path/to/noscrypt

# Set library paths
export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH
```

### Missing Dependencies

**Ubuntu/Debian:**
```bash
sudo apt install build-essential cmake libssl-dev libcjson-dev libwebsockets-dev
```

**macOS:**
```bash
brew install cmake openssl cjson libwebsockets
```

**Fedora/RHEL:**
```bash
sudo dnf install cmake openssl-devel cjson-devel libwebsockets-devel
```

## Build Options

- `CMAKE_BUILD_TYPE`: Set to `Release` for optimized builds or `Debug` for debugging
- `CMAKE_INSTALL_PREFIX`: Installation directory (default: `/usr/local`)
- `BUILD_SHARED_LIBS`: Build shared libraries (default: ON)
- `BUILD_TESTING`: Build test suite (default: ON)

Example:
```bash
cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/opt/nostr
```

## Installation

```bash
sudo make install
```

This installs:
- Headers to `<prefix>/include/`
- Libraries to `<prefix>/lib/`
- CMake configs to `<prefix>/lib/cmake/libnostr-c/`
- pkg-config file to `<prefix>/lib/pkgconfig/`

## Running Tests

```bash
# Run all tests
make test

# Or run individual test suites
./tests/test_runner
./tests/test_nip59
```

## Using in Your Project

### CMake

```cmake
find_package(libnostr-c REQUIRED)
target_link_libraries(your_app libnostr-c::nostr)
```

### pkg-config

```bash
gcc your_app.c $(pkg-config --cflags --libs libnostr-c)
```

### Manual Compilation

```bash
gcc your_app.c -lnostr -lssl -lcrypto -lcjson -lsecp256k1
```