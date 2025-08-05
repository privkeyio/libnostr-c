# Contributing to libnostr-c

Thank you for contributing to libnostr-c! This guide covers the essentials for getting started.

## Getting Started

### Prerequisites
- **C99 compatible compiler** (GCC 7+, Clang 6+)
- **CMake** 3.10+
- **Git** for version control
- **Dependencies**: libsecp256k1, libcjson, libwebsockets

### Setup
1. Fork and clone the repository:
   ```bash
   git clone https://github.com/YOUR_USERNAME/libnostr-c.git
   cd libnostr-c
   git remote add upstream https://github.com/privkeyio/libnostr-c.git
   ```

2. Install dependencies:
   ```bash
   # Ubuntu/Debian
   sudo apt install libsecp256k1-dev libcjson-dev libwebsockets-dev
   
   # macOS
   brew install libsecp256k1 libcjson libwebsockets
   ```

3. Build for development:
   ```bash
   mkdir build-dev && cd build-dev
   cmake -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTS=ON -DBUILD_EXAMPLES=ON ..
   make -j$(nproc)
   ```

## Workflow

1. **Create an issue** describing your change
2. **Create a feature branch**: `git checkout -b feature/description`
3. **Make changes** with clear commits
4. **Run tests**: `ctest --verbose`
5. **Submit a pull request**

## Coding Standards

### Naming Conventions
```c
// Functions: snake_case with nostr_ prefix
nostr_error_t nostr_event_create(nostr_event** event);

// Types: snake_case with nostr_ prefix and _t suffix  
typedef struct nostr_event nostr_event_t;

// Constants: UPPER_CASE with NOSTR_ prefix
#define NOSTR_MAX_CONTENT_SIZE 65536
```

### Code Style
- 4-space indentation
- Always check return values and malloc/calloc results
- Clear sensitive data: `memset(private_key, 0, sizeof(private_key))`
- Use consistent error handling with `nostr_error_t`

### Documentation
All public functions need Doxygen documentation:
```c
/**
 * @brief Create a new Nostr event
 * @param[out] event Pointer to store the created event
 * @return NOSTR_OK on success, error code otherwise
 */
nostr_error_t nostr_event_create(nostr_event** event);
```

## Testing

Write unit tests for all new functionality:
```c
void test_new_feature_basic_functionality(void) {
    nostr_error_t result = nostr_new_feature();
    TEST_ASSERT_EQUAL(NOSTR_OK, result);
}
```

Run tests with:
```bash
ctest --verbose
valgrind --leak-check=full ./tests/test_runner
```

## Security

- Validate all inputs
- Use constant-time implementations for crypto
- Clear sensitive data from memory
- All cryptographic changes require security review

## Commit Format

```
type(scope): brief description

Detailed explanation if needed.

Fixes #123
```

**Types**: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`

## Getting Help

- **Issues**: GitHub issues for bugs and features
- **Discussions**: GitHub discussions for questions
- **Documentation**: Check docs/ directory

Thank you for contributing!

