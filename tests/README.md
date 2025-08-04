# libnostr-c Test Suite

This directory contains comprehensive tests for the libnostr-c library.

## Running Tests

### Prerequisites
```bash
sudo apt-get install cmake pkg-config libssl-dev libcjson-dev libsecp256k1-dev libwebsockets-dev valgrind
```

### Build and Run
```bash
mkdir build && cd build
cmake ..
make
./tests/test_runner
```

### Memory Leak Testing
```bash
# Install valgrind first
sudo apt-get install valgrind

# Run memory leak tests
valgrind --tool=memcheck --leak-check=full ./tests/test_runner
```

## Test Structure

- `test_runner.c` - Main test runner
- `test_event.c` - Event creation, serialization, signing tests
- `test_key.c` - Key generation and cryptographic tests  
- `test_bech32.c` - Bech32 encoding/decoding tests
- `test_relay.c` - WebSocket relay communication tests
- `test_zap.c` - Lightning zap functionality tests
- `unity.h` - Minimal Unity test framework

## Coverage

The test suite covers:
- All public API functions
- Error handling paths
- Memory management
- Protocol compliance (NIP-01, NIP-19, NIP-57)
- Integration scenarios

## CI/CD

GitHub Actions automatically runs tests on push/PR to ensure code quality.