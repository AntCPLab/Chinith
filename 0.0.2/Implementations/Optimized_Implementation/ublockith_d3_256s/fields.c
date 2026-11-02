/* Keep the 64/256-bit fields used by uBlock signatures;
 * remove the unused AES/SM4/128-bit chain, including its faulty PCLMUL helper. */
#include "fields.h"
#include "utils.h"

// GF(2^64): X^64 + X^4 + X^3 + X + 1.
#define bf64_modulus (UINT64_C((1 << 4) | (1 << 3) | (1 << 1) | 1))
// GF(2^256): X^256 + X^10 + X^5 + X^2 + 1.
#define bf256_modulus (UINT64_C((1 << 10) | (1 << 5) | (1 << 2) | 1))

// GF(2^64) implementation

#if defined(__x86_64__) && defined(__PCLMUL__) && defined(UBLOCKITH_FIELD_PCLMUL)
bf64_t bf64_mul(bf64_t lhs, bf64_t rhs) {
  const __m128i a = _mm_set_epi64x(0, (long long)lhs);
  const __m128i b = _mm_set_epi64x(0, (long long)rhs);
  const __m128i r = _mm_set_epi64x(0, (long long)bf64_modulus);

  uint64_t p[2];
  _mm_storeu_si128((__m128i*)p, _mm_clmulepi64_si128(a, b, 0x00));
  uint64_t lo = p[0];
  uint64_t hi = p[1];

  uint64_t q[2];
  _mm_storeu_si128((__m128i*)q,
                   _mm_clmulepi64_si128(_mm_set_epi64x(0, (long long)hi), r, 0x00));
  lo ^= q[0];

  /* q[1] has degree <= 3; one extra fold is sufficient. */
  if (q[1]) {
    uint64_t q2[2];
    _mm_storeu_si128((__m128i*)q2,
                     _mm_clmulepi64_si128(_mm_set_epi64x(0, (long long)q[1]), r, 0x00));
    lo ^= q2[0];
  }
  return lo;
}
#else
bf64_t bf64_mul(bf64_t lhs, bf64_t rhs) {
  bf64_t result = (-(rhs & 1)) & lhs;
  for (unsigned int idx = 1; idx != 64; ++idx) {
    const uint64_t mask = -((lhs >> 63) & 1);
    lhs                 = (lhs << 1) ^ (mask & bf64_modulus);
    result ^= (-((rhs >> idx) & 1)) & lhs;
  }
  return result;
}
#endif

#define bf64_bit_to_mask(value, bit) -((((uint64_t)(value)) >> (bit)) & 1)

#if defined(__x86_64__) && defined(__PCLMUL__) && defined(UBLOCKITH_FIELD_PCLMUL)
static inline void xor_m128i_to_array(uint64_t* C, int idx, __m128i r) {
    uint64_t tmp[2];
    _mm_storeu_si128((__m128i*)tmp, r);
    C[idx] ^= tmp[0];
    C[idx+1] ^= tmp[1];
}
#endif

static inline bf256_t bf256_and_64(bf256_t lhs, bf64_t rhs) {
  for (unsigned int i = 0; i != ARRAY_SIZE(lhs.values); ++i) {
    lhs.values[i] &= rhs;
  }
  return lhs;
}

static inline bf256_t bf256_shift_left_1(bf256_t value) {
  value.values[3] = (value.values[3] << 1) | (value.values[2] >> 63);
  value.values[2] = (value.values[2] << 1) | (value.values[1] >> 63);
  value.values[1] = (value.values[1] << 1) | (value.values[0] >> 63);
  value.values[0] = value.values[0] << 1;
  return value;
}

static inline uint64_t bf256_bit_to_uint64_mask(bf256_t value,
                                                                              unsigned int bit) {
  const unsigned int byte_idx = bit / 64;
  const unsigned int bit_idx  = bit % 64;

  return -((BF_VALUE(value, byte_idx) >> bit_idx) & 1);
}

#if defined(__x86_64__) && defined(__PCLMUL__) && defined(UBLOCKITH_FIELD_PCLMUL)
/*
 * bf256_mul — 2×2 Karatsuba over GF(2)[x] using PCLMUL.
 *
 * Let A = A1·x^128 + A0  and  B = B1·x^128 + B0  (each half is 128 bits).
 * Karatsuba gives:
 *   full = A1·B1·x^256 + (A0·B1 ⊕ A1·B0)·x^128 + A0·B0
 * with the cross term computed as:
 *   A0·B1 ⊕ A1·B0 = (A0⊕A1)·(B0⊕B1) ⊕ A0·B0 ⊕ A1·B1
 *
 * Each 128×128 CLMUL uses 4 64×64 CLMULs and produces a 256-bit result.
 * Total: 3 × 4 = 12 CLMULs vs the naive 4×4=16.
 *
 * Reduction of the 512-bit product mod x^256+x^10+x^5+x^2+1:
 *   bf256_modulus = 0x425 = (1<<10)|(1<<5)|(1<<2)|1
 *   High 256 bits H = T[3]:T[2].  H · x^256 ≡ H · 0x425 (mod p).
 *   Two-step reduction:
 *     1. Reduce T[3] (128-bit) → at most 138-bit result, XOR into T[1]:T[2]
 *     2. Reduce updated T[2] (128-bit) → at most 138-bit result, XOR into T[0]:T[1]
 *     After step 2 the leftover bits in T[1] are at most 10 bits and cannot
 *     push anything back into T[2].
 */
static void bf128x2_clmul(const __m128i a, const __m128i b,
                            __m128i* lo, __m128i* hi) {
    /* 128×128 → 256-bit carryless multiply; result in (*hi):(*lo) */
    __m128i r00 = _mm_clmulepi64_si128(a, b, 0x00);
    __m128i r11 = _mm_clmulepi64_si128(a, b, 0x11);
    __m128i mid = _mm_xor_si128(_mm_clmulepi64_si128(a, b, 0x01),
                                 _mm_clmulepi64_si128(a, b, 0x10));
    *lo = _mm_xor_si128(r00, _mm_slli_si128(mid, 8));
    *hi = _mm_xor_si128(r11, _mm_srli_si128(mid, 8));
}

bf256_t bf256_mul(bf256_t lhs, bf256_t rhs) {
    __m128i a0 = _mm_loadu_si128((const __m128i*)&lhs.values[0]);
    __m128i a1 = _mm_loadu_si128((const __m128i*)&lhs.values[2]);
    __m128i b0 = _mm_loadu_si128((const __m128i*)&rhs.values[0]);
    __m128i b1 = _mm_loadu_si128((const __m128i*)&rhs.values[2]);

    /* p00 = a0 * b0,  p11 = a1 * b1 */
    __m128i p00lo, p00hi, p11lo, p11hi;
    bf128x2_clmul(a0, b0, &p00lo, &p00hi);
    bf128x2_clmul(a1, b1, &p11lo, &p11hi);

    /* pmid = (a0^a1) * (b0^b1) */
    __m128i pmlo, pmhi;
    bf128x2_clmul(_mm_xor_si128(a0, a1), _mm_xor_si128(b0, b1), &pmlo, &pmhi);

    /* cross = pmid ^ p00 ^ p11  (256-bit XOR) */
    __m128i cxlo = _mm_xor_si128(pmlo, _mm_xor_si128(p00lo, p11lo));
    __m128i cxhi = _mm_xor_si128(pmhi, _mm_xor_si128(p00hi, p11hi));

    /* Assemble 512-bit product as T[0..3]:
     *   T[0] = p00lo            bits [  0..127]
     *   T[1] = p00hi ^ cxlo     bits [128..255]
     *   T[2] = p11lo ^ cxhi     bits [256..383]
     *   T[3] = p11hi            bits [384..511]
     */
    __m128i T0 = p00lo;
    __m128i T1 = _mm_xor_si128(p00hi, cxlo);
    __m128i T2 = _mm_xor_si128(p11lo, cxhi);
    __m128i T3 = p11hi;

    /* Reduce mod x^256 + x^10 + x^5 + x^2 + 1 (bf256_modulus = 0x425).
     *
     * Step 1: Reduce T[3] (represents coefficient of x^384..x^511) into T[1]:T[2].
     *   T3 * 0x425 gives a value ≤ 138 bits.
     *   Low 128 bits XOR into T[1], high ≤10 bits XOR into low of T[2].
     */
    __m128i poly  = _mm_set_epi64x(0, (int64_t)bf256_modulus);
    __m128i r3lo  = _mm_clmulepi64_si128(T3, poly, 0x00);   /* T3.lo64 * 0x425 */
    __m128i r3hi  = _mm_clmulepi64_si128(T3, poly, 0x01);   /* T3.hi64 * 0x425 */
    /* Combine: 128-bit result lo + shifted hi */
    __m128i red3lo = _mm_xor_si128(r3lo, _mm_slli_si128(r3hi, 8));
    __m128i red3hi = _mm_srli_si128(r3hi, 8);   /* at most 10+1 bits, fits in low 64 */
    T1 = _mm_xor_si128(T1, red3lo);
    T2 = _mm_xor_si128(T2, red3hi);

    /* Step 2: Reduce updated T[2] into T[0]:T[1]. Same logic. */
    __m128i r2lo  = _mm_clmulepi64_si128(T2, poly, 0x00);
    __m128i r2hi  = _mm_clmulepi64_si128(T2, poly, 0x01);
    __m128i red2lo = _mm_xor_si128(r2lo, _mm_slli_si128(r2hi, 8));
    __m128i red2hi = _mm_srli_si128(r2hi, 8);
    T0 = _mm_xor_si128(T0, red2lo);
    T1 = _mm_xor_si128(T1, red2hi);
    /* red2hi is at most 10 bits and now sits in low 64 of T[1] — no further overflow. */

    bf256_t out;
    _mm_storeu_si128((__m128i*)&out.values[0], T0);
    _mm_storeu_si128((__m128i*)&out.values[2], T1);
    return out;
}
#else
bf256_t bf256_mul(bf256_t lhs, bf256_t rhs) {
  bf256_t result = bf256_and_64(lhs, bf256_bit_to_uint64_mask(rhs, 0));
  for (unsigned int idx = 1; idx != 256; ++idx) {
    const uint64_t mask = bf256_bit_to_uint64_mask(lhs, 256 - 1);
    lhs                 = bf256_shift_left_1(lhs);
    BF_VALUE(lhs, 0) ^= mask & bf256_modulus;

    result = bf256_add(result, bf256_and_64(lhs, bf256_bit_to_uint64_mask(rhs, idx)));
  }
  return result;
}
#endif

#if defined(__x86_64__) && defined(__PCLMUL__) && defined(UBLOCKITH_FIELD_PCLMUL)
bf256_t bf256_mul_64(bf256_t lhs, bf64_t rhs) {
    uint64_t C[6] = {0};
    __m128i b = _mm_set_epi64x(0, rhs);
    for (int i = 0; i < 4; i++) {
        __m128i a = _mm_set_epi64x(0, lhs.values[i]);
        __m128i r = _mm_clmulepi64_si128(a, b, 0x00);
        xor_m128i_to_array(C, i, r);
    }
    for (int i = 5; i >= 4; i--) {
        __m128i c = _mm_set_epi64x(0, C[i]);
        __m128i poly = _mm_set_epi64x(0, bf256_modulus);
        __m128i p = _mm_clmulepi64_si128(c, poly, 0x00);
        xor_m128i_to_array(C, i-4, p);
    }
    bf256_t out;
    out.values[0] = C[0];
    out.values[1] = C[1];
    out.values[2] = C[2];
    out.values[3] = C[3];
    return out;
}
#else
bf256_t bf256_mul_64(bf256_t lhs, bf64_t rhs) {
  bf256_t result = bf256_and_64(lhs, bf64_bit_to_mask(rhs, 0));
  for (unsigned int idx = 1; idx != 64; ++idx) {
    const uint64_t mask = bf256_bit_to_uint64_mask(lhs, 256 - 1);
    lhs                 = bf256_shift_left_1(lhs);
    BF_VALUE(lhs, 0) ^= mask & bf256_modulus;

    result = bf256_add(result, bf256_and_64(lhs, bf64_bit_to_mask(rhs, idx)));
  }
  return result;
}
#endif

bf256_t bf256_mul_bit(bf256_t lhs, uint8_t rhs) {
  return bf256_and_64(lhs, -((uint64_t)rhs & 1));
}

static inline bf256_t bf256_dbl(bf256_t lhs) {
  uint64_t mask = bf256_bit_to_uint64_mask(lhs, 256 - 1);
  lhs           = bf256_shift_left_1(lhs);
  BF_VALUE(lhs, 0) ^= mask & bf256_modulus;
  return lhs;
}

bf256_t bf256_sum_poly(const bf256_t* xs) {
  bf256_t ret = xs[256 - 1];
  for (size_t i = 1; i < 256; ++i) {
    ret = bf256_add(bf256_dbl(ret), xs[256 - 1 - i]);
  }
  return ret;
}

bf256_t bf256_sum_poly_bits(const uint8_t* xs) {
  bf256_t ret = bf256_from_bit(ptr_get_bit(xs, 256 - 1));
  for (size_t i = 1; i < 256; ++i) {
    ret = bf256_add(bf256_dbl(ret), bf256_from_bit(ptr_get_bit(xs, 256 - 1 - i)));
  }
  return ret;
}
