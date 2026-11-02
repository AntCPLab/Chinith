/* This instance uses only GF(2^64) and GF(2^256). */
#ifndef FIELDS_H
#define FIELDS_H

#include "macros.h"
#include "endian_compat.h"
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

typedef uint64_t bf64_t;
#define BF_VALUE(v, i) ((v).values[i])

typedef struct {
  uint64_t values[4];
} bf256_t;
#define BF256C(x0, x1, x2, x3)                                                                     \
  {                                                                                                \
    { x0, x1, x2, x3 }                                                                             \
  }
#define BF256_ALIGN 8
#define BF256_NUM_BYTES (256 / 8)

// GF(2^64) implementation

inline bf64_t bf64_load(const uint8_t* src) {
  bf64_t ret;
  memcpy(&ret, src, sizeof(ret));
  return ret;
}

static inline bf64_t bf64_zero(void) {
  return 0;
}

static inline bf64_t bf64_one(void) {
  return 1;
}

static inline bf64_t bf64_add(bf64_t lhs, bf64_t rhs) {
  return lhs ^ rhs;
}

bf64_t bf64_mul(bf64_t lhs, bf64_t rhs);

// GF(2^256) implementation

static inline bf256_t bf256_load(const uint8_t* src) {
  bf256_t ret;
  memcpy(&ret, src, BF256_NUM_BYTES);
  return ret;
}

static inline void bf256_store(uint8_t* dst, bf256_t src) {
  memcpy(dst, &src, BF256_NUM_BYTES);
}

static inline bf256_t bf256_from_bit(uint8_t bit) {
  const bf256_t ret = BF256C(bit & 1, 0, 0, 0);
  return ret;
}

static inline bf256_t bf256_zero(void) {
  const bf256_t ret = BF256C(0, 0, 0, 0);
  return ret;
}

static inline bf256_t bf256_one(void) {
  const bf256_t ret = BF256C(1, 0, 0, 0);
  return ret;
}

static inline bf256_t bf256_add(bf256_t lhs, bf256_t rhs) {
  for (unsigned int i = 0; i != ARRAY_SIZE(lhs.values); ++i) {
    lhs.values[i] ^= rhs.values[i];
  }
  return lhs;
}

bf256_t bf256_mul(bf256_t lhs, bf256_t rhs);
bf256_t bf256_mul_64(bf256_t lhs, bf64_t rhs);
bf256_t bf256_mul_bit(bf256_t lhs, uint8_t rhs);
bf256_t bf256_sum_poly(const bf256_t* xs);
bf256_t bf256_sum_poly_bits(const uint8_t* xs);

#endif
