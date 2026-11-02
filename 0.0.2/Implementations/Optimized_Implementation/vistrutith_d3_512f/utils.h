/*
 *  SPDX-License-Identifier: MIT
 */

#ifndef UTILS_H
#define UTILS_H

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#include "compat.h"
#include "macros.h"
#include "params.h"

#if defined(__x86_64__)
#include <immintrin.h>
#endif

/* XOR two byte arrays: out[i] = a[i] ^ b[i].
 * Uses AVX2 (32-byte chunks) or SSE2 (16-byte chunks) when available,
 * falling back to a scalar tail for any remaining bytes.
 * All three pointers may alias as long as 'out' equals 'a' or 'b'. */
static inline void xor_u8_array(const uint8_t* a, const uint8_t* b, uint8_t* out, size_t len) {
  size_t i = 0;
#if defined(__x86_64__) && defined(__AVX2__)
  for (; i + 32 <= len; i += 32) {
    __m256i va = _mm256_loadu_si256((const __m256i*)(a + i));
    __m256i vb = _mm256_loadu_si256((const __m256i*)(b + i));
    _mm256_storeu_si256((__m256i*)(out + i), _mm256_xor_si256(va, vb));
  }
#endif
#if defined(__x86_64__)  /* SSE2 is always available on x86-64 */
  for (; i + 16 <= len; i += 16) {
    __m128i va = _mm_loadu_si128((const __m128i*)(a + i));
    __m128i vb = _mm_loadu_si128((const __m128i*)(b + i));
    _mm_storeu_si128((__m128i*)(out + i), _mm_xor_si128(va, vb));
  }
#endif
  for (; i < len; i++) {
    out[i] = a[i] ^ b[i];
  }
}

/* Conditionally XOR: out[i] = a[i] ^ (b[i] & mask), where mask = 0xFF if
 * mask_bit is 1, 0x00 if mask_bit is 0. */
static inline void masked_xor_u8_array(const uint8_t* a, const uint8_t* b, uint8_t* out,
                                       uint8_t mask_bit, size_t len) {
  uint8_t mask = -(mask_bit & 1);
  size_t i = 0;
#if defined(__x86_64__)  /* SSE2 always available */
  __m128i vmask = _mm_set1_epi8((char)mask);
  for (; i + 16 <= len; i += 16) {
    __m128i va = _mm_loadu_si128((const __m128i*)(a + i));
    __m128i vb = _mm_loadu_si128((const __m128i*)(b + i));
    _mm_storeu_si128((__m128i*)(out + i), _mm_xor_si128(va, _mm_and_si128(vb, vmask)));
  }
#endif
  for (; i < len; i++) {
    out[i] = a[i] ^ (b[i] & mask);
  }
}

#define get_bit(value, index) (((value) >> (index)) & 1)
#define set_bit(value, index) ((value) << (index))
#define ptr_get_bit(value, index) (((value)[(index) / 8] >> ((index) % 8)) & 1)
#define ptr_set_bit(dst, index, value)                                                             \
  do {                                                                                             \
    const unsigned int ptr_set_bit_index_mod_8 = (index) % 8;                                      \
    (dst)[(index) / 8] = ((dst)[(index) / 8] & ~(1 << ptr_set_bit_index_mod_8)) |                  \
                         ((value) << ptr_set_bit_index_mod_8);                                     \
  } while (0)

// DecodeAllChall_3
bool decode_all_chall_3(const params_t* params, uint16_t* decoded_chall, const uint8_t* chall);

/* Removed unused local rotate and big-endian word helpers. */

#endif
