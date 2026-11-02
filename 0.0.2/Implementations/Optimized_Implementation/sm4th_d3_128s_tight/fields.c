/*
 *  Field implementation used by sm4th_d3_128s_tight.
 *  Keeps only domains exercised by this instance.
 *  GF(2^8) uses the SM4 polynomial x^8 + x^7 + x^6 + x^5 + x^4 + x^2 + 1
 */

#include "fields.h"
#include "x86_caps.h"
#include "utils.h"


// GF(2^64) with X^64 + X^4 + X^3 + X^1 + 1
#define bf64_modulus (UINT64_C((1 << 4) | (1 << 3) | (1 << 1) | 1))
// GF(2^160) with X^160 + X^5 + X^3 + X^2 + 1
#define bf160_modulus (UINT64_C((1 << 5) | (1 << 3) | (1 << 2) | 1))

#define U64C(x0, x1, x2, x3, x4, x5, x6, x7)                                                       \
  ((UINT64_C(x7) << 56) | (UINT64_C(x6) << 48) | (UINT64_C(x5) << 40) | (UINT64_C(x4) << 32) |     \
   (UINT64_C(x3) << 24) | (UINT64_C(x2) << 16) | (UINT64_C(x1) << 8) | UINT64_C(x0))

// GF(2^64) implementation

/* Retain ISA kernels behind a baseline runtime gate. */
#if SM4TH_COMPILE_PCLMUL
#include <immintrin.h>
typedef struct {
  __m128i v0;
  __m128i v1;
  __m128i v2;
} bf160_product_acc_t;

SM4TH_TARGET_PCLMUL static inline void bf160_clmul64(uint64_t lhs, uint64_t rhs, uint64_t* lo, uint64_t* hi) {
  const __m128i a = _mm_set_epi64x(0, (long long)lhs);
  const __m128i b = _mm_set_epi64x(0, (long long)rhs);
  uint64_t out[2];
  _mm_storeu_si128((__m128i*)out, _mm_clmulepi64_si128(a, b, 0x00));
  *lo = out[0];
  *hi = out[1];
}

SM4TH_TARGET_PCLMUL static inline void bf160_xor_pair(uint64_t* out, unsigned int offset,
                                  uint64_t lo, uint64_t hi) {
  out[offset] ^= lo;
  out[offset + 1] ^= hi;
}

SM4TH_TARGET_PCLMUL static inline bf160_t bf160_reduce_words(uint64_t t0, uint64_t t1, uint64_t t2,
                                         uint64_t t3, uint64_t t4, uint64_t t5) {
  const uint64_t h0 = (t2 >> 32) | (t3 << 32);
  const uint64_t h1 = (t3 >> 32) | (t4 << 32);
  const uint64_t h2 = ((t4 >> 32) | (t5 << 32)) & UINT64_C(0xffffffff);

  uint64_t r0 = t0 ^ h0 ^ (h0 << 2) ^ (h0 << 3) ^ (h0 << 5);
  uint64_t r1 = t1 ^ h1 ^
                ((h1 << 2) | (h0 >> 62)) ^
                ((h1 << 3) | (h0 >> 61)) ^
                ((h1 << 5) | (h0 >> 59));
  uint64_t r2 = (t2 & UINT64_C(0xffffffff)) ^ h2 ^
                ((h2 << 2) | (h1 >> 62)) ^
                ((h2 << 3) | (h1 >> 61)) ^
                ((h2 << 5) | (h1 >> 59));

  const uint64_t carry = r2 >> 32;
  r2 &= UINT64_C(0xffffffff);
  r0 ^= carry ^ (carry << 2) ^ (carry << 3) ^ (carry << 5);

  bf160_t out = BF160C(r0, r1, r2);
  return out;
}

SM4TH_TARGET_PCLMUL static inline void bf160_product_acc_zero(bf160_product_acc_t* acc) {
  acc->v0 = _mm_setzero_si128();
  acc->v1 = _mm_setzero_si128();
  acc->v2 = _mm_setzero_si128();
}

SM4TH_TARGET_PCLMUL static inline void bf160_product_acc_xor_field(bf160_product_acc_t* acc, const bf160_t* x) {
  acc->v0 = _mm_xor_si128(acc->v0, _mm_loadu_si128((const __m128i*)x->values));
  acc->v1 = _mm_xor_si128(
      acc->v1, _mm_cvtsi64_si128((long long)(x->values[2] & UINT64_C(0xffffffff))));
}

SM4TH_TARGET_PCLMUL static inline void bf160_product_acc_xor_product(bf160_product_acc_t* acc, const bf160_t* lhs,
                                                 const bf160_t* rhs) {
  const bf160_product_t product = bf160_mul_product_faest192_inline(lhs, rhs);
  acc->v0 = _mm_xor_si128(acc->v0, product.v0);
  acc->v1 = _mm_xor_si128(acc->v1, product.v1);
  acc->v2 = _mm_xor_si128(acc->v2, product.v2);
}

SM4TH_TARGET_PCLMUL static inline bf160_t bf160_product_acc_reduce(const bf160_product_acc_t* acc) {
  return bf160_inline_reduce_product_clmul(acc->v0, acc->v1, acc->v2);
}
#endif

#if SM4TH_COMPILE_PCLMUL
SM4TH_TARGET_PCLMUL static bf64_t bf64_mul_pclmul(bf64_t lhs, bf64_t rhs) {
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
#endif

bf64_t bf64_mul(bf64_t lhs, bf64_t rhs) {
#if SM4TH_COMPILE_PCLMUL
  if (sm4th_x86_has_pclmul()) { return bf64_mul_pclmul(lhs, rhs); }
#endif
  bf64_t result = (-(rhs & 1)) & lhs;
  for (unsigned int idx = 1; idx != 64; ++idx) {
    const uint64_t mask = -((lhs >> 63) & 1);
    lhs                 = (lhs << 1) ^ (mask & bf64_modulus);
    result ^= (-((rhs >> idx) & 1)) & lhs;
  }
  return result;
}

#define bf64_bit_to_mask(value, bit) -((((uint64_t)(value)) >> (bit)) & 1)

/* This tight instance uses GF(2^160), not the legacy GF(2^160) branch. */

// GF(2^160) implementation

static inline bf160_t bf160_and_64(bf160_t lhs, bf64_t rhs) {
  for (unsigned int i = 0; i != ARRAY_SIZE(lhs.values); ++i) {
    lhs.values[i] &= rhs;
  }
  BF_VALUE(lhs, 2) &= UINT64_C(0xffffffff);
  return lhs;
}

static inline bf160_t bf160_shift_left_1(bf160_t value) {
  value.values[2] = ((value.values[2] << 1) | (value.values[1] >> 63)) & UINT64_C(0xffffffff);
  value.values[1] = (value.values[1] << 1) | (value.values[0] >> 63);
  value.values[0] = value.values[0] << 1;
  return value;
}

static inline uint64_t bf160_bit_to_uint64_mask(bf160_t value, unsigned int bit) {
  const unsigned int byte_idx = bit / 64;
  const unsigned int bit_idx  = bit % 64;

  return -((BF_VALUE(value, byte_idx) >> bit_idx) & 1);
}

static inline bf160_t bf160_dbl(bf160_t lhs) {
  const uint64_t mask = bf160_bit_to_uint64_mask(lhs, 160 - 1);
  lhs                 = bf160_shift_left_1(lhs);
  BF_VALUE(lhs, 0) ^= mask & bf160_modulus;
  return lhs;
}

#if SM4TH_COMPILE_PCLMUL
SM4TH_TARGET_PCLMUL static void bf160_mul_out_pclmul(bf160_t* out, const bf160_t* lhs, const bf160_t* rhs) {
  bf160_mul_out_inline(out, lhs, rhs);
}
#endif

void bf160_mul_out(bf160_t* out, const bf160_t* lhs, const bf160_t* rhs) {
#if SM4TH_COMPILE_PCLMUL
  if (sm4th_x86_has_pclmul()) { bf160_mul_out_pclmul(out, lhs, rhs); return; }
#endif
  bf160_t lhs_copy = *lhs;
  const bf160_t rhs_copy =
      BF160C(rhs->values[0], rhs->values[1], rhs->values[2] & UINT64_C(0xffffffff));
  lhs_copy.values[2] &= UINT64_C(0xffffffff);

  bf160_t result = bf160_and_64(lhs_copy, bf160_bit_to_uint64_mask(rhs_copy, 0));
  for (unsigned int idx = 1; idx != 160; ++idx) {
    lhs_copy = bf160_dbl(lhs_copy);
    result   = bf160_add(result, bf160_and_64(lhs_copy, bf160_bit_to_uint64_mask(rhs_copy, idx)));
  }
  *out = result;
}

#if SM4TH_COMPILE_PCLMUL
SM4TH_TARGET_PCLMUL static bf160_t bf160_mul_pclmul(bf160_t lhs, bf160_t rhs) {
  return bf160_mul_inline(lhs, rhs);
}
#endif

bf160_t bf160_mul(bf160_t lhs, bf160_t rhs) {
#if SM4TH_COMPILE_PCLMUL
  if (sm4th_x86_has_pclmul()) { return bf160_mul_pclmul(lhs, rhs); }
#endif
  bf160_t result;
  bf160_mul_out(&result, &lhs, &rhs);
  return result;
}

#if SM4TH_COMPILE_PCLMUL
SM4TH_TARGET_PCLMUL static bf160_t bf160_sqr_pclmul(bf160_t lhs) {
  return bf160_sqr_inline(lhs);
}
#endif

bf160_t bf160_sqr(bf160_t lhs) {
#if SM4TH_COMPILE_PCLMUL
  if (sm4th_x86_has_pclmul()) { return bf160_sqr_pclmul(lhs); }
#endif
  return bf160_mul(lhs, lhs);
}

#if SM4TH_COMPILE_PCLMUL
SM4TH_TARGET_PCLMUL static bf160_t bf160_mul_64_pclmul(bf160_t lhs, bf64_t rhs) {
  uint64_t product[6] = {0, 0, 0, 0, 0, 0};
  for (unsigned int i = 0; i != 3; ++i) {
    uint64_t lo;
    uint64_t hi;
    bf160_clmul64(lhs.values[i] & (i == 2 ? UINT64_C(0xffffffff) : UINT64_MAX),
                  rhs, &lo, &hi);
    bf160_xor_pair(product, i, lo, hi);
  }
  return bf160_reduce_words(product[0], product[1], product[2],
                            product[3], product[4], product[5]);
}
#endif

bf160_t bf160_mul_64(bf160_t lhs, bf64_t rhs) {
#if SM4TH_COMPILE_PCLMUL
  if (sm4th_x86_has_pclmul()) { return bf160_mul_64_pclmul(lhs, rhs); }
#endif
  lhs.values[2] &= UINT64_C(0xffffffff);

  bf160_t result = bf160_and_64(lhs, bf64_bit_to_mask(rhs, 0));
  for (unsigned int idx = 1; idx != 64; ++idx) {
    lhs    = bf160_dbl(lhs);
    result = bf160_add(result, bf160_and_64(lhs, bf64_bit_to_mask(rhs, idx)));
  }
  return result;
}

bf160_t bf160_mul_bit(bf160_t lhs, uint8_t rhs) {
  return bf160_and_64(lhs, -((uint64_t)rhs & 1));
}

bf160_t bf160_sum_poly(const bf160_t* xs) {
  bf160_t ret = xs[160 - 1];
  for (size_t i = 1; i < 160; ++i) {
    ret = bf160_add(bf160_dbl(ret), xs[160 - 1 - i]);
  }
  return ret;
}

bf160_t bf160_sum_poly_bits(const uint8_t* xs) {
  bf160_t ret = bf160_from_bit(ptr_get_bit(xs, 160 - 1));
  for (size_t i = 1; i < 160; ++i) {
    ret = bf160_add(bf160_dbl(ret), bf160_from_bit(ptr_get_bit(xs, 160 - 1 - i)));
  }
  return ret;
}

/* ================================================================ */
/*  SM4-specific alpha array for byte_combine operations             */
/*  Roots of m(t) = t^8+t^7+t^6+t^5+t^4+t^2+1 in GF(2^160)           */
/* ================================================================ */

/* Powers of alpha_8: α^1, α^2, α^3, ..., α^7 for byte embedding
 * Used in bf160_byte_combine_bits_sm4: φ(x) = Σ(bit_i * α^i) */

static const bf160_t bf160_alpha_sm4_powers[7] = {
    /* α^1 */ BF160C(U64C(0xd5, 0x1d, 0x5b, 0x51, 0x62, 0xcb, 0x88, 0x67),
                     U64C(0xb3, 0xc6, 0x6e, 0x3e, 0x1f, 0xaa, 0x3b, 0x35),
                     UINT64_C(0x139c6970)),
    /* α^2 */ BF160C(U64C(0x35, 0x3c, 0x77, 0x91, 0x4c, 0x35, 0xf5, 0xee),
                     U64C(0xd6, 0x86, 0xb8, 0xcb, 0x40, 0x09, 0x7a, 0x7b),
                     UINT64_C(0x7d862197)),
    /* α^3 */ BF160C(U64C(0x22, 0x8e, 0x2e, 0x54, 0x19, 0x7c, 0x9b, 0xb8),
                     U64C(0x20, 0xb2, 0xe9, 0xd4, 0x1f, 0x28, 0x2a, 0x6d),
                     UINT64_C(0x4696bbf9)),
    /* α^4 */ BF160C(U64C(0x0b, 0xd7, 0x82, 0x9e, 0x1c, 0xc5, 0x6e, 0x4a),
                     U64C(0xa4, 0x52, 0xca, 0x47, 0x5a, 0x3a, 0x72, 0xe0),
                     UINT64_C(0x00a21370)),
    /* α^5 */ BF160C(U64C(0xba, 0xe6, 0xbb, 0x5e, 0xb7, 0x99, 0x21, 0x0c),
                     U64C(0x2f, 0x53, 0x49, 0x01, 0xcb, 0x9a, 0x24, 0xe5),
                     UINT64_C(0x7bfbe6eb)),
    /* α^6 */ BF160C(U64C(0x33, 0x2b, 0x8d, 0xff, 0x54, 0x20, 0x50, 0xae),
                     U64C(0xb5, 0xbe, 0xed, 0x78, 0x2a, 0x43, 0x90, 0x97),
                     UINT64_C(0x976b6b6f)),
    /* α^7 */ BF160C(U64C(0x07, 0xbd, 0x96, 0x2d, 0x41, 0xff, 0x48, 0xd5),
                     U64C(0x0c, 0x71, 0xc5, 0x81, 0xa6, 0xb7, 0x63, 0xd4),
                     UINT64_C(0x80bb0fc7)),
};

/* ================================================================ */
/*  SM4-specific GF(2^8) operations                                   */
/*  Polynomial: x^8 + x^7 + x^6 + x^5 + x^4 + x^2 + 1                */
/* ================================================================ */

#define bf8_modulus_sm4 \
    (UINT8_C((1 << 7) | (1 << 6) | (1 << 5) | (1 << 4) | (1 << 2) | 1))

/*
 * bits_sq_sm4: squaring in GF(2^8) with SM4 polynomial.
 * Derived from x^{2i} mod f(x), f = x^8+x^7+x^6+x^5+x^4+x^2+1:
 *    out[0] = b0 ^ b4
 *    out[1] = b5 ^ b7
 *    out[2] = b1 ^ b4 ^ b5
 *    out[3] = b5 ^ b6 ^ b7
 *    out[4] = b2 ^ b4 ^ b5 ^ b6
 *    out[5] = b4 ^ b5 ^ b6
 *    out[6] = b3 ^ b4 ^ b6
 *    out[7] = b4 ^ b6
 */
uint8_t bits_sq_sm4(uint8_t x) {
    uint8_t res;
    res  = set_bit(get_bit(x, 0) ^ get_bit(x, 4),                              0);
    res |= set_bit(get_bit(x, 5) ^ get_bit(x, 7),                              1);
    res |= set_bit(get_bit(x, 1) ^ get_bit(x, 4) ^ get_bit(x, 5),             2);
    res |= set_bit(get_bit(x, 5) ^ get_bit(x, 6) ^ get_bit(x, 7),             3);
    res |= set_bit(get_bit(x, 2) ^ get_bit(x, 4) ^ get_bit(x, 5)
                                 ^ get_bit(x, 6),                              4);
    res |= set_bit(get_bit(x, 4) ^ get_bit(x, 5) ^ get_bit(x, 6),             5);
    res |= set_bit(get_bit(x, 3) ^ get_bit(x, 4) ^ get_bit(x, 6),             6);
    res |= set_bit(get_bit(x, 4) ^ get_bit(x, 6),                             7);
    return res;
}

bf8_t bf8_mul_sm4(bf8_t lhs, bf8_t rhs) {
    bf8_t result = -(rhs & 1) & lhs;
    for (unsigned int idx = 1; idx < 8; ++idx) {
        const uint8_t mask = -((lhs >> 7) & 1);
        lhs    = (lhs << 1) ^ (mask & bf8_modulus_sm4);
        result ^= -((rhs >> idx) & 1) & lhs;
    }
    return result;
}

bf8_t bf8_square_sm4(bf8_t lhs) {
    bf8_t result = -(lhs & 1) & lhs;
    bf8_t rhs    = lhs;
    for (unsigned int idx = 1; idx < 8; ++idx) {
        const uint8_t mask = -((lhs >> 7) & 1);
        lhs    = (lhs << 1) ^ (mask & bf8_modulus_sm4);
        result ^= -((rhs >> idx) & 1) & lhs;
    }
    return result;
}

bf8_t bf8_inv_sm4(bf8_t in) {
    const bf8_t t2   = bf8_square_sm4(in);          /* in^2   */
    const bf8_t t3   = bf8_mul_sm4(in, t2);         /* in^3   */
    const bf8_t t5   = bf8_mul_sm4(t3, t2);         /* in^5   */
    const bf8_t t7   = bf8_mul_sm4(t5, t2);         /* in^7   */
    const bf8_t t14  = bf8_square_sm4(t7);          /* in^14  */
    const bf8_t t28  = bf8_square_sm4(t14);         /* in^28  */
    const bf8_t t56  = bf8_square_sm4(t28);         /* in^56  */
    const bf8_t t63  = bf8_mul_sm4(t56, t7);        /* in^63  */
    const bf8_t t126 = bf8_square_sm4(t63);         /* in^126 */
    const bf8_t t252 = bf8_square_sm4(t126);        /* in^252 */
    return bf8_mul_sm4(t252, t2);                   /* in^254 */
}

/* ================================================================ */
/*  SM4-specific bf160 squaring operations                           */
/* ================================================================ */


#if SM4TH_COMPILE_PCLMUL
SM4TH_TARGET_PCLMUL static bf160_t bf160_byte_combine_sm4_pclmul(const bf160_t* x) {
  bf160_product_acc_t acc;
  bf160_product_acc_zero(&acc);
  bf160_product_acc_xor_field(&acc, &x[0]);
  for (unsigned int i = 1; i < 8; ++i) {
    bf160_product_acc_xor_product(&acc, &x[i], &bf160_alpha_sm4_powers[i - 1]);
  }
  return bf160_product_acc_reduce(&acc);
}
#endif

bf160_t bf160_byte_combine_sm4(const bf160_t* x) {
#if SM4TH_COMPILE_PCLMUL
  if (sm4th_x86_has_pclmul()) { return bf160_byte_combine_sm4_pclmul(x); }
#endif
  bf160_t bf_out = x[0];
  for (unsigned int i = 1; i < 8; ++i) {
    bf_out = bf160_add(bf_out, bf160_mul(x[i], bf160_alpha_sm4_powers[i - 1]));
  }
  return bf_out;
}

bf160_t bf160_byte_combine_bits_sm4(uint8_t x) {
  bf160_t bf_out = bf160_from_bit(get_bit(x, 0));
  for (unsigned int i = 1; i < 8; ++i) {
    bf_out = bf160_add(bf_out, bf160_mul_bit(bf160_alpha_sm4_powers[i - 1], get_bit(x, i)));
  }
  return bf_out;
}

void bf160_sq_bit_sm4(bf160_t* out_tag, const bf160_t* in_tag) {
  out_tag[0] = bf160_add(in_tag[0], in_tag[4]);
  out_tag[1] = bf160_add(in_tag[5], in_tag[7]);
  out_tag[2] = bf160_add(in_tag[1], bf160_add(in_tag[4], in_tag[5]));
  out_tag[3] = bf160_add(in_tag[5], bf160_add(in_tag[6], in_tag[7]));
  out_tag[4] = bf160_add(in_tag[2], bf160_add(in_tag[4], bf160_add(in_tag[5], in_tag[6])));
  out_tag[5] = bf160_add(in_tag[4], bf160_add(in_tag[5], in_tag[6]));
  out_tag[6] = bf160_add(in_tag[3], bf160_add(in_tag[4], in_tag[6]));
  out_tag[7] = bf160_add(in_tag[4], in_tag[6]);
}

void bf160_sq_bit_inplace_sm4(bf160_t* tag) {
  tag[0] = bf160_add(tag[0], tag[4]);

  const bf160_t i1 = tag[1];
  tag[1] = bf160_add(tag[5], tag[7]);

  const bf160_t i2 = tag[2];
  tag[2] = bf160_add(i1, bf160_add(tag[4], tag[5]));

  const bf160_t i3 = tag[3];
  tag[3] = bf160_add(tag[5], bf160_add(tag[6], tag[7]));

  const bf160_t i4 = tag[4];
  tag[4] = bf160_add(i2, bf160_add(i4, bf160_add(tag[5], tag[6])));

  tag[5] = bf160_add(i4, bf160_add(tag[5], tag[6]));

  const bf160_t i6 = tag[6];
  tag[6] = bf160_add(i3, bf160_add(i4, i6));

  tag[7] = bf160_add(i4, i6);
}

bf160_t bf160_byte_combine_sq_sm4(const bf160_t* x) {
  bf160_t tmp[8];
  bf160_sq_bit_sm4(tmp, x);
  return bf160_byte_combine_sm4(tmp);
}

bf160_t bf160_byte_combine_bits_sq_sm4(uint8_t x) {
  return bf160_byte_combine_bits_sm4(bits_sq_sm4(x));
}

/* Unused field-only pseudo-random helpers were removed. */
