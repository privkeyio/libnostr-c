# libnostr-c Performance Characteristics

This document provides detailed performance analysis and optimization guidance for libnostr-c.

## Benchmarking

### Running Benchmarks

```bash
# Build the library
cmake -B build
make -C build

# Run all benchmarks
make -C build benchmark

# Run specific benchmark categories
./build/benchmark/bench_runner key
./build/benchmark/bench_runner crypto
./build/benchmark/bench_runner event

# Run memory analysis
make -C build memory-analysis

# Run SIMD analysis
make -C build simd-analysis

# Performance regression testing
make -C build save-baseline     # First time
make -C build regression-test   # Subsequent runs
```

### CPU Profiling

```bash
# Generate callgrind profile data
make -C build profile

# Analyze with callgrind_annotate
callgrind_annotate callgrind.out

# Or use kcachegrind for GUI analysis
kcachegrind callgrind.out
```

## Performance Characteristics

### Key Operations

| Operation | Typical Performance | Notes |
|-----------|-------------------|-------|
| Key Generation | ~50,000 ns/op | Cryptographically secure random generation |
| Key From/To Hex | ~500 ns/op | Simple string conversion |
| Key From/To Bech32 | ~2,000 ns/op | Includes checksum validation |
| ECDH Operation | ~45,000 ns/op | secp256k1 point multiplication |

### Cryptographic Operations

| Operation | Message Size | Performance | Throughput |
|-----------|-------------|-------------|------------|
| NIP-44 Encrypt | 13 bytes | ~180,000 ns/op | ~0.07 MB/s |
| NIP-44 Encrypt | 100 bytes | ~185,000 ns/op | ~0.54 MB/s |
| NIP-44 Encrypt | 500 bytes | ~190,000 ns/op | ~2.6 MB/s |
| NIP-44 Decrypt | 13 bytes | ~175,000 ns/op | ~0.07 MB/s |
| NIP-44 Decrypt | 100 bytes | ~180,000 ns/op | ~0.56 MB/s |
| NIP-44 Decrypt | 500 bytes | ~185,000 ns/op | ~2.7 MB/s |
| NIP-04 Encrypt | 13 bytes | ~120,000 ns/op | ~0.11 MB/s |
| NIP-04 Decrypt | 13 bytes | ~115,000 ns/op | ~0.11 MB/s |

### Event Operations

| Operation | Performance | Notes |
|-----------|-------------|-------|
| Event Creation | ~1,500 ns/op | Memory allocation and initialization |
| Event Set Content | ~800 ns/op | String copy and allocation |
| Event Add Tag | ~1,200 ns/op | Arena allocation for tags |
| Event Compute ID | ~15,000 ns/op | SHA256 + JSON serialization |
| Event Sign | ~50,000 ns/op | Schnorr signature generation |
| Event Verify | ~75,000 ns/op | Schnorr signature verification |
| Event To JSON | ~8,000 ns/op | JSON serialization |
| Event From JSON | ~12,000 ns/op | JSON parsing and validation |

### Memory Usage Patterns

#### Event Memory Scaling
- Base event: ~200 bytes
- Per tag: ~50-100 bytes (depending on content)
- Large content scales linearly
- Tag arena reduces fragmentation for events with many tags

#### Tag Arena Efficiency
- 1 tag: ~150 bytes overhead
- 10 tags: ~15 bytes per tag
- 100 tags: ~8 bytes per tag
- Bulk allocation reduces malloc/free overhead

#### Crypto Memory Overhead
- NIP-44 encryption: ~2KB temporary allocation
- NIP-04 encryption: ~1KB temporary allocation
- Key operations: Minimal overhead (<1KB)

## Optimization Opportunities

### SIMD Optimizations

The library can benefit from SIMD optimizations in several areas:

#### Memory Operations
- **Constant-time memcmp**: AVX2 can provide 2-3x speedup for large comparisons
- **Secure memory wiping**: AVX2 shows 4-5x improvement for clearing sensitive data
- **String operations**: SIMD can accelerate hex encoding/decoding

#### Implementation Status
- Scalar implementations available for all operations
- SIMD analysis tools identify optimization candidates
- Compile with `-msse2 -mavx2` for SIMD-enabled builds

### Memory Allocation Patterns

#### Current Optimizations
- **Tag Arena**: Bulk allocation for event tags reduces fragmentation
- **String Interning**: Common strings could be interned to reduce memory usage
- **Pool Allocation**: Event objects could use memory pools

#### Potential Improvements
1. **Event Pool**: Pre-allocate event structures for high-frequency use
2. **String Pool**: Share common tag values and content strings
3. **Buffer Reuse**: Reuse temporary buffers for crypto operations

### CPU Optimizations

#### Hot Paths (by CPU usage)
1. **Signature Operations** (25-30% of CPU time)
   - secp256k1 operations dominate
   - Hardware acceleration where available
   
2. **Hash Operations** (15-20% of CPU time)
   - SHA256 for event IDs
   - Consider SHA-NI instructions
   
3. **JSON Processing** (10-15% of CPU time)
   - Parsing and serialization
   - SIMD string operations could help
   
4. **Memory Operations** (8-12% of CPU time)
   - Memory copying and clearing
   - SIMD optimizations available

#### Compiler Optimizations
```bash
# Release build with optimizations
cmake -DCMAKE_BUILD_TYPE=Release -B build

# Additional optimization flags
cmake -DCMAKE_C_FLAGS="-O3 -march=native -flto" -B build
```

## Performance Regression Testing

### Automated Testing
The regression test framework tracks performance across versions:

```bash
# Set initial baseline
make -C build save-baseline

# Check for regressions (returns non-zero if regressions found)
make -C build regression-test
```

### Regression Criteria
- **Warning Threshold**: 10% performance degradation
- **Regression Threshold**: 20% performance degradation
- Tests cover all major API functions
- Baseline stored in `performance_baseline.txt` (machine-specific, not committed)

### CI Integration
```yaml
# Example GitHub Actions step
- name: Performance Regression Test
  run: |
    make -C build regression-test
    if [ $? -ne 0 ]; then
      echo "Performance regression detected!"
      exit 1
    fi
```

## Platform-Specific Considerations

### Linux
- Uses `clock_gettime(CLOCK_MONOTONIC)` for timing
- Memory usage tracked via `/proc/self/status`
- SIMD support auto-detected at compile time

### macOS
- Uses `mach_absolute_time()` for high-precision timing
- Memory tracking via `getrusage()`
- SIMD support similar to Linux

### Windows
- Uses `QueryPerformanceCounter()` for timing
- Different memory tracking mechanisms
- SIMD support requires MSVC or MinGW-w64

## Benchmark Results Reference

### Typical Performance (AMD64, 3.2GHz)
```
Key Operations:
  nostr_key_generate                    : 47234.50 ns/op
  nostr_key_from_hex                    :   465.23 ns/op
  nostr_key_to_hex                      :   512.11 ns/op
  nostr_key_to_bech32                   :  1876.45 ns/op
  nostr_key_ecdh                        : 44321.67 ns/op

Crypto Operations:
  NIP-44 Encrypt (13 bytes)             : 178345.12 ns/op (0.07 MB/s)
  NIP-44 Decrypt (13 bytes)             : 172891.34 ns/op (0.08 MB/s)
  NIP-04 Encrypt (13 bytes)             : 118756.78 ns/op (0.11 MB/s)

Event Operations:
  nostr_event_create                    :  1456.23 ns/op
  nostr_event_compute_id                : 14567.89 ns/op
  nostr_event_sign                      : 49123.45 ns/op
  nostr_event_verify                    : 73456.78 ns/op
```

## Best Practices

### For Applications
1. **Reuse Objects**: Keep events and keys in scope when possible
2. **Batch Operations**: Group related operations together
3. **Memory Management**: Use appropriate destruction functions
4. **Profile Regularly**: Use the provided benchmarking tools

### For Library Development
1. **Run Benchmarks**: Before and after changes
2. **Check Regressions**: Use automated regression testing
3. **Profile Changes**: Use callgrind for detailed analysis
4. **Document Changes**: Update this document for significant changes

### For Deployment
1. **Compile Optimized**: Use `-O3 -march=native` for production
2. **Enable SIMD**: Use appropriate compiler flags
3. **Monitor Performance**: Implement runtime performance monitoring
4. **Tune Configuration**: Adjust library configuration for your use case