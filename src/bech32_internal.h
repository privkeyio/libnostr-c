#ifndef BECH32_INTERNAL_H
#define BECH32_INTERNAL_H

#include <stdint.h>
#include <stddef.h>

extern const char BECH32_CHARSET[33];
extern const uint32_t BECH32_GENERATOR[5];

uint32_t bech32_polymod(const uint8_t* values, size_t len);
int bech32_hrp_expand(const char* hrp, uint8_t* ret, size_t ret_size);
int bech32_verify_checksum(const char* hrp, const uint8_t* data, size_t data_len);
int bech32_create_checksum(const char* hrp, const uint8_t* data, size_t data_len, uint8_t* checksum);
int bech32_convert_bits(const uint8_t* in, size_t inlen, uint8_t* out, size_t outlen, int frombits, int tobits, int pad);
int bech32_charset_decode(char c);

#endif
