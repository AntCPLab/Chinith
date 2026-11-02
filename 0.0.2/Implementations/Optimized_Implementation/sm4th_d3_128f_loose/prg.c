/*
 * SPDX-License-Identifier: MIT
 *
 * Pseudorandom generator (PRG) selection and wrappers.
 */
#include "prg.h"
#include "compat.h"

#include "utils_sm4/sm4.h"
#include "x86_caps.h"

#ifndef SM4TH_ENABLE_HYGON_CIS
#define SM4TH_ENABLE_HYGON_CIS 0
#endif

#if SM4TH_ENABLE_HYGON_CIS && defined(__x86_64__)
#include "utils_sm4/hygon_cis_sm4.h"
#endif

#if defined(__x86_64__) || defined(__i386__)
#include <x86intrin.h>
#endif

#include <assert.h>
#include <string.h>

#ifndef PRG_BLOCK_SIZE
#define PRG_BLOCK_SIZE SM4_BLOCK_SIZE
#endif

#ifndef PRG_BATCH_BLOCKS
#define PRG_BATCH_BLOCKS 32
#endif

#if SM4TH_ENABLE_SM4_ACCE && (defined(__x86_64__) || defined(__i386__))
#define PRG_HAS_SM4_FASTPATH 1
#else
#define PRG_HAS_SM4_FASTPATH 0
#endif

#if SM4TH_ENABLE_HYGON_CIS && defined(__x86_64__)
#define PRG_HAS_HYGON_CIS_FASTPATH 1
#else
#define PRG_HAS_HYGON_CIS_FASTPATH 0
#endif

#define PRG_HAS_INTEL_SM4_NI SM4TH_NATIVE_SM4_COMPILED

#if PRG_HAS_SM4_FASTPATH
/* The optional assembly uses the Linux x86-64 ABI only. */
#if defined(__linux__) && defined(__x86_64__)
extern void sm4_aesni_avx2_asm_ecb_enc_blk_16(unsigned int* rk, unsigned char* dst,
                                          unsigned char* src) __attribute__((weak));
#else
static void (*const sm4_aesni_avx2_asm_ecb_enc_blk_16)(unsigned int*, unsigned char*,
                                                     unsigned char*) = NULL;
#endif


void sm4_encrypt4_opt(const uint32_t *rk, const void *src, const void *dst);

void yuchen_sm4_key_schedule_impl(const uint8_t *key, uint32_t *rk);
#endif

static inline void prg_increment_iv(uint8_t* iv) {
  uint32_t iv0;
  memcpy(&iv0, iv, sizeof(uint32_t));
  iv0 = htole32(le32toh(iv0) + 1);
  memcpy(iv, &iv0, sizeof(uint32_t));
}

static void add_to_upper_word(uint8_t* iv, uint32_t tweak) {
  uint32_t iv3;
  memcpy(&iv3, iv + PRG_BLOCK_SIZE - sizeof(uint32_t), sizeof(uint32_t));
  iv3 = htole32(le32toh(iv3) + tweak);
  memcpy(iv + PRG_BLOCK_SIZE - sizeof(uint32_t), &iv3, sizeof(uint32_t));
}

/* Compile optional detectors only when their callers are compiled. */
#if PRG_HAS_INTEL_SM4_NI
/* Native support is published by the shared once-only detector. */
static inline int prg_has_intel_sm4_ni_runtime_cached(void) {
  return intel_sm4_ni_supported();
}
#endif

#if PRG_HAS_SM4_FASTPATH
static inline int prg_has_sm4_fastpath_runtime(void) {
  /* SM4NI needs AES+SSSE3; only the 16-block assembly needs AVX2. */
  return sm4th_x86_has_aes_ssse3();
}
#endif

static inline int prg_has_sm4_fastpath_runtime_cached(void) {
#if PRG_HAS_SM4_FASTPATH
  /* Publish feature-cache values atomically across callers. */
  static atomic_int cached = ATOMIC_VAR_INIT(-1);
  int value = atomic_load_explicit(&cached, memory_order_acquire);
  if (value < 0) {
    value = prg_has_sm4_fastpath_runtime() ? 1 : 0;
    atomic_store_explicit(&cached, value, memory_order_release);
  }
  return value;
#else
  return 0;
#endif
}

#if PRG_HAS_HYGON_CIS_FASTPATH
static inline int prg_has_hygon_cis_fastpath_runtime_cached(void) {
  /* Publish feature-cache values atomically across callers. */
  static atomic_int cached = ATOMIC_VAR_INIT(-1);
  int value = atomic_load_explicit(&cached, memory_order_acquire);
  if (value < 0) {
    value = hygon_cis_sm4_is_supported() ? 1 : 0;
    atomic_store_explicit(&cached, value, memory_order_release);
  }
  return value;
}
#endif

#if PRG_HAS_SM4_FASTPATH
static inline uint32_t prg_load_u32_be(const uint8_t* p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) |
         (uint32_t)p[3];
}

/* All callers already require AES+SSSE3; expand four SM4 keys
 * with the encryption kernel's register-only S-box and the key-schedule L'. */
/* Share the AES kernel; select its F+VL specialization once per batch. */
__attribute__((target("ssse3,aes"), always_inline)) static inline void
sm4_key_schedule_interleaved_4_body(const uint8_t* keys, size_t key_stride,
                                           uint32_t rks[4][SM4_KEY_SCHEDULE]) {
  const __m128i c0f = {0x0F0F0F0F0F0F0F0FULL, 0x0F0F0F0F0F0F0F0FULL};
  const __m128i shr = {0x0B0E0104070A0D00ULL, 0x0306090C0F020508ULL};
  const __m128i m1l = {0x9197E2E474720701ULL, 0xC7C1B4B222245157ULL};
  const __m128i m1h = {0xE240AB09EB49A200ULL, 0xF052B91BF95BB012ULL};
  const __m128i m2l = {0x5B67F2CEA19D0834ULL, 0xEDD14478172BBE82ULL};
  const __m128i m2h = {0xAE7201DD73AFDC00ULL, 0x11CDBE62CC1063BFULL};
  uint32_t words[4][4];

  for (size_t lane = 0; lane < 4; ++lane) {
    for (size_t word = 0; word < 4; ++word) {
      words[word][lane] = prg_load_u32_be(keys + lane * key_stride + 4 * word) ^ FK[word];
    }
  }
  __m128i k0 = _mm_loadu_si128((const __m128i*)words[0]);
  __m128i k1 = _mm_loadu_si128((const __m128i*)words[1]);
  __m128i k2 = _mm_loadu_si128((const __m128i*)words[2]);
  __m128i k3 = _mm_loadu_si128((const __m128i*)words[3]);

  for (size_t i = 0; i < SM4_KEY_SCHEDULE; ++i) {
    __m128i x = k1 ^ k2 ^ k3 ^ _mm_set1_epi32((int)CK[i]);
    __m128i y = _mm_shuffle_epi8(m1l, _mm_and_si128(x, c0f));
    x = _mm_and_si128(_mm_srli_epi64(x, 4), c0f);
    x = _mm_shuffle_epi8(m1h, x) ^ y;
    x = _mm_shuffle_epi8(x, shr);
    x = _mm_aesenclast_si128(x, c0f);
    y = _mm_shuffle_epi8(m2l, _mm_andnot_si128(x, c0f));
    x = _mm_and_si128(_mm_srli_epi64(x, 4), c0f);
    x = _mm_shuffle_epi8(m2h, x) ^ y;

    x ^= (_mm_slli_epi32(x, 13) ^ _mm_srli_epi32(x, 19)) ^
         (_mm_slli_epi32(x, 23) ^ _mm_srli_epi32(x, 9));
    x ^= k0;
    k0 = k1;
    k1 = k2;
    k2 = k3;
    k3 = x;
    _mm_storeu_si128((__m128i*)words[0], x);
    for (size_t lane = 0; lane < 4; ++lane) {
      rks[lane][i] = words[0][lane];
    }
  }
}

__attribute__((target("ssse3,aes"))) static void
sm4_key_schedule_interleaved_4(const uint8_t* keys, size_t key_stride,
                                           uint32_t rks[4][SM4_KEY_SCHEDULE]) {
  sm4_key_schedule_interleaved_4_body(keys, key_stride, rks);
}

__attribute__((target("ssse3,aes,avx2,avx512f,avx512vl"))) static void
sm4_key_schedule_interleaved_4_avx512(const uint8_t* keys, size_t key_stride,
                                           uint32_t rks[4][SM4_KEY_SCHEDULE]) {
  sm4_key_schedule_interleaved_4_body(keys, key_stride, rks);
}

/* Reuse AES+SSSE3 expansion for single keys and residual batches. */
static void prg_sm4_expand_key1(const uint8_t* key, uint32_t* rk) {
  if (prg_has_sm4_fastpath_runtime_cached()) {
    uint32_t rks[4][SM4_KEY_SCHEDULE];
    sm4_key_schedule_interleaved_4(key, 0, rks);
    memcpy(rk, rks[0], sizeof(rks[0]));
    return;
  }
  yuchen_sm4_key_schedule_impl(key, rk);
}

// adapted from sm4_encrypt4_opt in sm4ni.c to encrypt 4 blocks with 4 different keys in parallel
// dst[lane] = SM4_Encrypt(rks[lane], src[lane])，lane=0..3。
#if defined(__x86_64__) || defined(__i386__)
/* Share the AES kernel; select its F+VL specialization once per batch. */
__attribute__((target("ssse3,aes"), always_inline)) static inline void
sm4_encrypt4_diffkeys_1blk_body(uint32_t rks[4][SM4_KEY_SCHEDULE], const uint8_t* src, uint8_t* dst) {
  const __m128i c0f __attribute__((aligned(0x10))) = {0x0F0F0F0F0F0F0F0FULL,
                                                       0x0F0F0F0F0F0F0F0FULL};
  const __m128i flp __attribute__((aligned(0x10))) = {0x0405060700010203ULL,
                                                       0x0C0D0E0F08090A0BULL};
  const __m128i shr __attribute__((aligned(0x10))) = {0x0B0E0104070A0D00ULL,
                                                       0x0306090C0F020508ULL};
  const __m128i m1l __attribute__((aligned(0x10))) = {0x9197E2E474720701ULL,
                                                       0xC7C1B4B222245157ULL};
  const __m128i m1h __attribute__((aligned(0x10))) = {0xE240AB09EB49A200ULL,
                                                       0xF052B91BF95BB012ULL};
  const __m128i m2l __attribute__((aligned(0x10))) = {0x5B67F2CEA19D0834ULL,
                                                       0xEDD14478172BBE82ULL};
  const __m128i m2h __attribute__((aligned(0x10))) = {0xAE7201DD73AFDC00ULL,
                                                       0x11CDBE62CC1063BFULL};
  const __m128i r08 __attribute__((aligned(0x10))) = {0x0605040702010003ULL,
                                                       0x0E0D0C0F0A09080BULL};
  const __m128i r16 __attribute__((aligned(0x10))) = {0x0504070601000302ULL,
                                                       0x0D0C0F0E09080B0AULL};
  const __m128i r24 __attribute__((aligned(0x10))) = {0x0407060500030201ULL,
                                                       0x0C0F0E0D080B0A09ULL};

  __m128i x, y, t0, t1, t2, t3;
  uint32_t v[4] __attribute__((aligned(0x10)));
  const uint32_t* p32 = (const uint32_t*)src;

  t0 = _mm_set_epi32(p32[12], p32[8], p32[4], p32[0]);
  t0 = _mm_shuffle_epi8(t0, flp);
  t1 = _mm_set_epi32(p32[13], p32[9], p32[5], p32[1]);
  t1 = _mm_shuffle_epi8(t1, flp);
  t2 = _mm_set_epi32(p32[14], p32[10], p32[6], p32[2]);
  t2 = _mm_shuffle_epi8(t2, flp);
  t3 = _mm_set_epi32(p32[15], p32[11], p32[7], p32[3]);
  t3 = _mm_shuffle_epi8(t3, flp);

  for (int i = 0; i < 32; ++i) {
    const __m128i rk = _mm_set_epi32((int)rks[3][i], (int)rks[2][i], (int)rks[1][i],
                                     (int)rks[0][i]);
    x                = t1 ^ t2 ^ t3 ^ rk;

    y = _mm_and_si128(x, c0f);
    y = _mm_shuffle_epi8(m1l, y);
    x = _mm_srli_epi64(x, 4);
    x = _mm_and_si128(x, c0f);
    x = _mm_shuffle_epi8(m1h, x) ^ y;

    x = _mm_shuffle_epi8(x, shr);
    x = _mm_aesenclast_si128(x, c0f);

    y = _mm_andnot_si128(x, c0f);
    y = _mm_shuffle_epi8(m2l, y);
    x = _mm_srli_epi64(x, 4);
    x = _mm_and_si128(x, c0f);
    x = _mm_shuffle_epi8(m2h, x) ^ y;

    y = x ^ _mm_shuffle_epi8(x, r08) ^ _mm_shuffle_epi8(x, r16);
    y = _mm_slli_epi32(y, 2) ^ _mm_srli_epi32(y, 30);
    x = x ^ y ^ _mm_shuffle_epi8(x, r24);

    x ^= t0;
    t0 = t1;
    t1 = t2;
    t2 = t3;
    t3 = x;
  }

  uint32_t* out32 = (uint32_t*)dst;
  _mm_store_si128((__m128i*)v, _mm_shuffle_epi8(t3, flp));
  out32[0] = v[0];
  out32[4] = v[1];
  out32[8] = v[2];
  out32[12] = v[3];
  _mm_store_si128((__m128i*)v, _mm_shuffle_epi8(t2, flp));
  out32[1] = v[0];
  out32[5] = v[1];
  out32[9] = v[2];
  out32[13] = v[3];
  _mm_store_si128((__m128i*)v, _mm_shuffle_epi8(t1, flp));
  out32[2] = v[0];
  out32[6] = v[1];
  out32[10] = v[2];
  out32[14] = v[3];
  _mm_store_si128((__m128i*)v, _mm_shuffle_epi8(t0, flp));
  out32[3] = v[0];
  out32[7] = v[1];
  out32[11] = v[2];
  out32[15] = v[3];
}

__attribute__((target("ssse3,aes"))) static void
sm4_encrypt4_diffkeys_1blk(uint32_t rks[4][SM4_KEY_SCHEDULE], const uint8_t* src, uint8_t* dst) {
  sm4_encrypt4_diffkeys_1blk_body(rks, src, dst);
}

__attribute__((target("ssse3,aes,avx2,avx512f,avx512vl"))) static void
sm4_encrypt4_diffkeys_1blk_avx512(uint32_t rks[4][SM4_KEY_SCHEDULE], const uint8_t* src, uint8_t* dst) {
  sm4_encrypt4_diffkeys_1blk_body(rks, src, dst);
}

#endif

static inline void prg_sm4_ctr2_from_rk(const uint32_t* rk, const uint8_t* iv, uint32_t tweak,
                                        uint8_t* out) {
  uint8_t ctr[4 * PRG_BLOCK_SIZE];
  uint8_t enc[4 * PRG_BLOCK_SIZE];
  memcpy(ctr, iv, PRG_BLOCK_SIZE);
  add_to_upper_word(ctr, tweak);
  memcpy(ctr + PRG_BLOCK_SIZE, ctr, PRG_BLOCK_SIZE);
  prg_increment_iv(ctr + PRG_BLOCK_SIZE);
  // Fill the unused lanes to keep one 4-block SM4NI call.
  memcpy(ctr + 2 * PRG_BLOCK_SIZE, ctr, PRG_BLOCK_SIZE);
  memcpy(ctr + 3 * PRG_BLOCK_SIZE, ctr + PRG_BLOCK_SIZE, PRG_BLOCK_SIZE);
  sm4_encrypt4_opt(rk, ctr, enc);
  memcpy(out, enc, 2 * PRG_BLOCK_SIZE);
}
#endif

#if PRG_HAS_HYGON_CIS_FASTPATH
static inline void prg_prepare_ctr2(const uint8_t* iv, uint32_t tweak,
                                    uint8_t ctr2[2 * PRG_BLOCK_SIZE]) {
  memcpy(ctr2, iv, PRG_BLOCK_SIZE);
  add_to_upper_word(ctr2, tweak);
  memcpy(ctr2 + PRG_BLOCK_SIZE, ctr2, PRG_BLOCK_SIZE);
  prg_increment_iv(ctr2 + PRG_BLOCK_SIZE);
}

static inline void prg_prepare_ctr2x4(const uint8_t* iv, uint32_t tweak_base,
                                      uint32_t tweak_step, size_t index,
                                      uint8_t ctr2x4[4 * 2 * PRG_BLOCK_SIZE]) {
  for (size_t lane = 0; lane < 4; ++lane) {
    prg_prepare_ctr2(iv, tweak_base + tweak_step * (uint32_t)(index + lane),
                     ctr2x4 + lane * 2 * PRG_BLOCK_SIZE);
  }
}

static inline void prg_hygon_ctr2_from_key(const uint8_t* key, const uint8_t* iv,
                                           uint32_t tweak, uint8_t* out) {
  uint8_t ctr2[2 * PRG_BLOCK_SIZE];
  prg_prepare_ctr2(iv, tweak, ctr2);
  hygon_cis_sm4_prg_2lambda_from_key(key, ctr2, out);
}
#endif

static void generic_prg(const uint8_t* key, uint8_t* internal_iv, uint8_t* out,
                        unsigned int seclvl, size_t outlen) {
  assert(seclvl == 128 || seclvl == 256);
  /* SM4-CTR PRG only. */
  generic_sm4_ecb_t ctx;
  int ret = generic_sm4_ecb_new(&ctx, key, seclvl);
  assert(ret == 0);
  (void)ret;

  uint8_t counter_blocks[PRG_BATCH_BLOCKS * PRG_BLOCK_SIZE];
  size_t full_blocks = outlen / PRG_BLOCK_SIZE;

  while (full_blocks) {
    const size_t batch_blocks = full_blocks > PRG_BATCH_BLOCKS ? PRG_BATCH_BLOCKS : full_blocks;

    for (size_t i = 0; i < batch_blocks; ++i) {
      memcpy(counter_blocks + i * PRG_BLOCK_SIZE, internal_iv, PRG_BLOCK_SIZE);
      prg_increment_iv(internal_iv);
    }

    ret = generic_sm4_ecb_encrypt(&ctx, out, counter_blocks, batch_blocks);
    assert(ret == 0);
    (void)ret;

    out += batch_blocks * PRG_BLOCK_SIZE;
    full_blocks -= batch_blocks;
  }

  if (outlen % PRG_BLOCK_SIZE) {
    uint8_t last_block[PRG_BLOCK_SIZE];
    ret = generic_sm4_ecb_encrypt(&ctx, last_block, internal_iv, 1);
    assert(ret == 0);
    (void)ret;
    memcpy(out, last_block, outlen % PRG_BLOCK_SIZE);
  }

  generic_sm4_ecb_free(&ctx);
}


#if PRG_HAS_INTEL_SM4_NI
/* Preserve current IV/tweak encoding with JoCR native counters. */
static inline void prg_intel_sm4_prepare_ctr2(const uint8_t* iv, uint32_t tweak,
                                               uint8_t ctr[2][PRG_BLOCK_SIZE]) {
  memcpy(ctr[0], iv, PRG_BLOCK_SIZE);
  add_to_upper_word(ctr[0], tweak);
  memcpy(ctr[1], ctr[0], PRG_BLOCK_SIZE);
  prg_increment_iv(ctr[1]);
}

static inline void prg_intel_sm4_ctr2_from_rk(const uint32_t rk[SM4_KEY_SCHEDULE],
                                               const uint8_t* iv, uint32_t tweak,
                                               uint8_t* out) {
  uint8_t ctr[2][PRG_BLOCK_SIZE];
  uint8_t enc[2][PRG_BLOCK_SIZE];
  prg_intel_sm4_prepare_ctr2(iv, tweak, ctr);
  intel_sm4_ni_encrypt2_same_key(
      rk, (const uint8_t (*)[PRG_BLOCK_SIZE])(const void*)ctr, enc);
  memcpy(out, enc, 2u * PRG_BLOCK_SIZE);
}
#endif

static inline void prg_2_lambda_single_impl(const uint8_t* key, const uint8_t* iv, uint32_t tweak,
                                             uint8_t* out, unsigned int seclvl,
                                             int use_sm4_fastpath) {
#if PRG_HAS_INTEL_SM4_NI
/* Native SM4 is preferred; packed schedules serve both PRG outputs. */
  if (seclvl == 128u && prg_has_intel_sm4_ni_runtime_cached()) {
    uint32_t rk[SM4_KEY_SCHEDULE];
    intel_sm4_ni_expand_key1(key, rk);
    prg_intel_sm4_ctr2_from_rk(rk, iv, tweak, out);
    return;
  }
#endif

#if PRG_HAS_HYGON_CIS_FASTPATH
  if (seclvl == 128u && prg_has_hygon_cis_fastpath_runtime_cached()) {
    prg_hygon_ctr2_from_key(key, iv, tweak, out);
    return;
  }
#endif
#if PRG_HAS_SM4_FASTPATH
  if (use_sm4_fastpath) {
    uint32_t rk[SM4_KEY_SCHEDULE];
    prg_sm4_expand_key1(key, rk);
    prg_sm4_ctr2_from_rk(rk, iv, tweak, out);
    return;
  }
#else
  (void)use_sm4_fastpath;
#endif

  uint8_t internal_iv[PRG_BLOCK_SIZE];
  memcpy(internal_iv, iv, PRG_BLOCK_SIZE);
  add_to_upper_word(internal_iv, tweak);
  generic_prg(key, internal_iv, out, seclvl, seclvl * 2 / 8);
}

// - run sm4_key_schedule_interleaved_4 for 4 lane round keys (different keys).
// - prepare two counter blocks for each lane: ctr0 and ctr1=ctr0+1.
// - call sm4_encrypt4_diffkeys_1blk twice to encrypt ctr0/ctr1.
// - concatenate the results for each lane to form 32B output (2 SM4 blocks).
static void prg_2_lambda_independent_batch_impl(const uint8_t* keys, size_t key_stride,
                                                const uint8_t* iv, uint32_t tweak_base,
                                                uint32_t tweak_step, uint8_t* out,
                                                size_t out_stride, unsigned int seclvl,
                                                size_t count) {
  if (count == 0) {
    return;
  }

#if PRG_HAS_INTEL_SM4_NI
/* Native SM4 is preferred; packed schedules serve both PRG outputs. */
  if (prg_has_intel_sm4_ni_runtime_cached() && seclvl == 128u && out_stride == 32u) {
    size_t i = 0;
    while (i + 4u <= count) {
      uint32_t rks[4][SM4_KEY_SCHEDULE];
      intel_sm4_ni_expand_key4(keys + i * key_stride, (unsigned long)key_stride, rks);
      for (size_t lane = 0; lane < 4u; ++lane) {
        prg_intel_sm4_ctr2_from_rk(
            rks[lane], iv, tweak_base + tweak_step * (uint32_t)(i + lane),
            out + (i + lane) * out_stride);
      }
      i += 4u;
    }
    for (; i < count; ++i) {
      uint32_t rk[SM4_KEY_SCHEDULE];
      intel_sm4_ni_expand_key1(keys + i * key_stride, rk);
      prg_intel_sm4_ctr2_from_rk(rk, iv, tweak_base + tweak_step * (uint32_t)i,
                                 out + i * out_stride);
    }
    return;
  }
#endif

#if PRG_HAS_HYGON_CIS_FASTPATH
  if (prg_has_hygon_cis_fastpath_runtime_cached() && seclvl == 128 && out_stride == 32) {
    size_t i = 0;
    while (i + 4 <= count) {
      uint8_t ctr2x4[4 * 2 * PRG_BLOCK_SIZE];
      prg_prepare_ctr2x4(iv, tweak_base, tweak_step, i, ctr2x4);
      hygon_cis_sm4_prg_2lambda_4way_from_key(keys + i * key_stride, key_stride, ctr2x4,
                                              out + i * out_stride, out_stride);
      i += 4;
    }
    for (; i < count; ++i) {
      prg_hygon_ctr2_from_key(keys + i * key_stride, iv,
                              tweak_base + tweak_step * (uint32_t)i, out + i * out_stride);
    }
    return;
  }
#endif

#if PRG_HAS_SM4_FASTPATH
  if (prg_has_sm4_fastpath_runtime_cached() && seclvl == 128 && out_stride == 32) {
    const int use_sm4_fvl = sm4th_x86_has_avx512f_vl();
    size_t i = 0;
    while (i + 4 <= count) {
      uint32_t rks[4][SM4_KEY_SCHEDULE];
      uint8_t ctr0[4 * PRG_BLOCK_SIZE];
      uint8_t ctr1[4 * PRG_BLOCK_SIZE];
      uint8_t enc0[4 * PRG_BLOCK_SIZE];
      uint8_t enc1[4 * PRG_BLOCK_SIZE];

      if (use_sm4_fvl) {
        sm4_key_schedule_interleaved_4_avx512(keys + i * key_stride, key_stride, rks);
      } else {
        sm4_key_schedule_interleaved_4(keys + i * key_stride, key_stride, rks);
      }

      for (size_t lane = 0; lane < 4; ++lane) {
        uint8_t* ctr0_lane = ctr0 + lane * PRG_BLOCK_SIZE;
        uint8_t* ctr1_lane = ctr1 + lane * PRG_BLOCK_SIZE;
        memcpy(ctr0_lane, iv, PRG_BLOCK_SIZE);
        add_to_upper_word(ctr0_lane, tweak_base + tweak_step * (uint32_t)(i + lane));
        memcpy(ctr1_lane, ctr0_lane, PRG_BLOCK_SIZE);
        prg_increment_iv(ctr1_lane);
      }

#if defined(__x86_64__) || defined(__i386__)
      if (use_sm4_fvl) {
        sm4_encrypt4_diffkeys_1blk_avx512(rks, ctr0, enc0);
        sm4_encrypt4_diffkeys_1blk_avx512(rks, ctr1, enc1);
      } else {
        sm4_encrypt4_diffkeys_1blk(rks, ctr0, enc0);
        sm4_encrypt4_diffkeys_1blk(rks, ctr1, enc1);
      }
      for (size_t lane = 0; lane < 4; ++lane) {
        uint8_t* out_lane = out + (i + lane) * out_stride;
        memcpy(out_lane, enc0 + lane * PRG_BLOCK_SIZE, PRG_BLOCK_SIZE);
        memcpy(out_lane + PRG_BLOCK_SIZE, enc1 + lane * PRG_BLOCK_SIZE, PRG_BLOCK_SIZE);
      }
#else
      for (size_t lane = 0; lane < 4; ++lane) {
        prg_sm4_ctr2_from_rk(rks[lane], iv, tweak_base + (uint32_t)(i + lane),
                             out + (i + lane) * out_stride);
      }
#endif
      i += 4;
    }

    for (; i < count; ++i) {
      uint32_t rk[SM4_KEY_SCHEDULE];
      prg_sm4_expand_key1(keys + i * key_stride, rk);
      prg_sm4_ctr2_from_rk(rk, iv, tweak_base + tweak_step * (uint32_t)i, out + i * out_stride);
    }
    return;
  }
#endif

  const int use_sm4_fastpath = (seclvl == 128) && prg_has_sm4_fastpath_runtime_cached();
  for (size_t i = 0; i < count; ++i) {
    const uint8_t* key_i = keys + i * key_stride;
    uint8_t* out_i = out + i * out_stride;
    prg_2_lambda_single_impl(key_i, iv, tweak_base + tweak_step * (uint32_t)i, out_i, seclvl,
                             use_sm4_fastpath);
  }
}

void prg_2_lambda_independent_batch(const uint8_t* keys, size_t key_stride, const uint8_t* iv,
                                    uint32_t tweak_base, uint8_t* out, size_t out_stride,
                                    unsigned int seclvl, size_t count) {
  prg_2_lambda_independent_batch_impl(keys, key_stride, iv, tweak_base, 1, out, out_stride,
                                      seclvl, count);
}

static inline uint8_t* prg_sd_xor_map_slot(uint8_t* sd_out, size_t sd_stride, size_t index,
                                           size_t sd_index_base, size_t sd_index_xor) {
  const size_t mapped = (sd_index_base + index) ^ sd_index_xor;
  if (mapped == 0) {
    return NULL;
  }
  return sd_out + mapped * sd_stride;
}

#if PRG_HAS_SM4_FASTPATH || PRG_HAS_HYGON_CIS_FASTPATH
static inline void prg_prepare_counters_16_plus_tail4(const uint8_t* iv, uint32_t tweak,
                                                      uint8_t ctr16[16 * PRG_BLOCK_SIZE],
                                                      uint8_t ctr_tail4[4 * PRG_BLOCK_SIZE]) {
  uint8_t internal_iv[PRG_BLOCK_SIZE];
  uint8_t suffix[PRG_BLOCK_SIZE - sizeof(uint32_t)];
  uint32_t ctr_base_le;
  uint32_t ctr_base;

  memcpy(internal_iv, iv, PRG_BLOCK_SIZE);
  add_to_upper_word(internal_iv, tweak);
  memcpy(&ctr_base_le, internal_iv, sizeof(uint32_t));
  ctr_base = le32toh(ctr_base_le);
  memcpy(suffix, internal_iv + sizeof(uint32_t), sizeof(suffix));

  for (uint32_t blk = 0; blk < 16; ++blk) {
    const size_t off = (size_t)blk * PRG_BLOCK_SIZE;
    const uint32_t ctr = htole32(ctr_base + blk);
    memcpy(ctr16 + off, &ctr, sizeof(uint32_t));
    memcpy(ctr16 + off + sizeof(uint32_t), suffix, sizeof(suffix));
  }

  for (uint32_t lane = 0; lane < 4; ++lane) {
    const uint32_t ctr = htole32(ctr_base + 16 + lane);
    memcpy(ctr_tail4 + lane * PRG_BLOCK_SIZE, &ctr, sizeof(uint32_t));
    memcpy(ctr_tail4 + lane * PRG_BLOCK_SIZE + sizeof(uint32_t), suffix, sizeof(suffix));
  }
}
#endif

#define PRG_276_BYTES 276u
#define PRG_HYGON_FUSED_276_BYTES 276u

#if PRG_HAS_INTEL_SM4_NI
/* Reuse four packed key schedules for the 2-counter and 6-counter kernels. */
static inline void prg_intel_sm4_276_from_rk(const uint32_t rk[SM4_KEY_SCHEDULE],
                                             const uint8_t* iv, uint32_t tweak,
                                             uint8_t out[PRG_276_BYTES]) {
  uint8_t counter[PRG_BLOCK_SIZE];
  memcpy(counter, iv, sizeof(counter));
  add_to_upper_word(counter, tweak);
  for (size_t pair_index = 0; pair_index < 9u; ++pair_index) {
    uint8_t ctr[2][PRG_BLOCK_SIZE];
    uint8_t enc[2][PRG_BLOCK_SIZE];
    memcpy(ctr[0], counter, PRG_BLOCK_SIZE);
    prg_increment_iv(counter);
    memcpy(ctr[1], counter, PRG_BLOCK_SIZE);
    prg_increment_iv(counter);
    intel_sm4_ni_encrypt2_same_key(
        rk, (const uint8_t (*)[PRG_BLOCK_SIZE])(const void*)ctr, enc);
    const size_t offset = pair_index * 2u * PRG_BLOCK_SIZE;
    const size_t remaining = PRG_276_BYTES - offset;
    const size_t take = remaining < 2u * PRG_BLOCK_SIZE ? remaining : 2u * PRG_BLOCK_SIZE;
    memcpy(out + offset, enc, take);
  }
}

static inline void prg_intel_sm4_2lambda_batch4(
    const intel_sm4_ni_rk4_packed* rks, const uint8_t* iv, uint32_t tweak,
    uint8_t* out0, uint8_t* out1, uint8_t* out2, uint8_t* out3) {
  uint8_t ctr[2][PRG_BLOCK_SIZE];
  prg_intel_sm4_prepare_ctr2(iv, tweak, ctr);
  intel_sm4_ni_encrypt4_keys_2blocks_packed(
      rks, (const uint8_t (*)[PRG_BLOCK_SIZE])(const void*)ctr,
      out0, out1, out2, out3);
}

static inline void prg_intel_sm4_276_batch4(
    const intel_sm4_ni_rk4_packed* rks, const uint8_t* iv, uint32_t tweak,
    uint8_t* out0, uint8_t* out1, uint8_t* out2, uint8_t* out3) {
  uint8_t counter[PRG_BLOCK_SIZE];
  memcpy(counter, iv, sizeof(counter));
  add_to_upper_word(counter, tweak);
  for (size_t chunk = 0; chunk < 3u; ++chunk) {
    uint8_t ctr[6][PRG_BLOCK_SIZE];
    for (size_t block = 0; block < 6u; ++block) {
      memcpy(ctr[block], counter, PRG_BLOCK_SIZE);
      prg_increment_iv(counter);
    }
    const size_t offset = chunk * 6u * PRG_BLOCK_SIZE;
    if (chunk < 2u) {
      intel_sm4_ni_encrypt4_keys_6blocks_packed(
          rks, (const uint8_t (*)[PRG_BLOCK_SIZE])(const void*)ctr,
          out0 + offset, out1 + offset, out2 + offset, out3 + offset);
    } else {
      uint8_t tail[4][6 * PRG_BLOCK_SIZE];
      intel_sm4_ni_encrypt4_keys_6blocks_packed(
          rks, (const uint8_t (*)[PRG_BLOCK_SIZE])(const void*)ctr,
          tail[0], tail[1], tail[2], tail[3]);
      const size_t take = PRG_276_BYTES - offset;
      memcpy(out0 + offset, tail[0], take);
      memcpy(out1 + offset, tail[1], take);
      memcpy(out2 + offset, tail[2], take);
      memcpy(out3 + offset, tail[3], take);
    }
  }
}
#endif

#if PRG_HAS_HYGON_CIS_FASTPATH
static inline void prg_hygon_276_from_rk_precomp(const uint32_t* rk,
                                                 const uint8_t ctr16[16 * PRG_BLOCK_SIZE],
                                                 const uint8_t ctr_tail4[4 * PRG_BLOCK_SIZE],
                                                 uint8_t* out) {
  uint8_t tail2[2 * PRG_BLOCK_SIZE];

  hygon_cis_sm4_encrypt_blocks(rk, ctr16, out, 16);
  hygon_cis_sm4_encrypt_blocks(rk, ctr_tail4, tail2, 2);
  memcpy(out + 256, tail2, PRG_276_BYTES - 256u);
}

static inline void prg_hygon_2lambda_276_from_key_precomp(
    const uint8_t* key, const uint8_t ctr2[2 * PRG_BLOCK_SIZE],
    const uint8_t ctr16[16 * PRG_BLOCK_SIZE], const uint8_t ctr_tail4[4 * PRG_BLOCK_SIZE],
    uint8_t* out2, uint8_t* out276) {
  hygon_cis_sm4_prg_2lambda_276_from_key(key, ctr2, out2, ctr16, ctr_tail4, out276);
}

static inline void prg_hygon_276_from_rk(const uint32_t* rk, const uint8_t* iv, uint32_t tweak,
                                         uint8_t* out) {
  uint8_t ctr16[16 * PRG_BLOCK_SIZE];
  uint8_t ctr_tail4[4 * PRG_BLOCK_SIZE];

  prg_prepare_counters_16_plus_tail4(iv, tweak, ctr16, ctr_tail4);
  prg_hygon_276_from_rk_precomp(rk, ctr16, ctr_tail4, out);
}
#endif

#if PRG_HAS_SM4_FASTPATH
static inline void prg_276_first16_from_rk_precomp_mode(
    const uint32_t* rk, const uint8_t ctr16[16 * PRG_BLOCK_SIZE], int use_ecb16,
    uint8_t* out) {
  if (use_ecb16) {
    sm4_aesni_avx2_asm_ecb_enc_blk_16((unsigned int*)rk, out, (unsigned char*)ctr16);
    return;
  }
  for (uint32_t grp = 0; grp < 4; ++grp) {
    sm4_encrypt4_opt(rk, ctr16 + (size_t)grp * 4 * PRG_BLOCK_SIZE,
                     out + (size_t)grp * 4 * PRG_BLOCK_SIZE);
  }
}

static inline void prg_276_from_rk_precomp_mode(const uint32_t* rk,
                                                const uint8_t ctr16[16 * PRG_BLOCK_SIZE],
                                                const uint8_t ctr_tail4[4 * PRG_BLOCK_SIZE],
                                                int use_ecb16, uint8_t* out) {
  uint8_t tail4[PRG_BLOCK_SIZE * 4];

  prg_276_first16_from_rk_precomp_mode(rk, ctr16, use_ecb16, out);
  sm4_encrypt4_opt(rk, ctr_tail4, tail4);
  memcpy(out + 256, tail4, PRG_276_BYTES - 256u);
}

static inline void prg_276_from_rk(const uint32_t* rk, const uint8_t* iv, uint32_t tweak,
                                   uint8_t* out) {
  uint8_t ctr16[16 * PRG_BLOCK_SIZE];
  uint8_t ctr_tail4[4 * PRG_BLOCK_SIZE];
  const int use_ecb16 =
      (sm4_aesni_avx2_asm_ecb_enc_blk_16 != NULL) && sm4th_x86_has_aes_ssse3() &&
      sm4th_x86_has_avx2();
  prg_prepare_counters_16_plus_tail4(iv, tweak, ctr16, ctr_tail4);
  prg_276_from_rk_precomp_mode(rk, ctr16, ctr_tail4, use_ecb16, out);
}

#if defined(__x86_64__) || defined(__i386__)
static inline void prg_276_batch4_generate_precomp_mode(
    uint32_t rks[4][SM4_KEY_SCHEDULE], const uint8_t ctr16[16 * PRG_BLOCK_SIZE],
    const uint8_t ctr_tail4[4 * PRG_BLOCK_SIZE], int use_ecb16, uint8_t* out0, uint8_t* out1,
    uint8_t* out2, uint8_t* out3) {
  if (!out0 && !out1 && !out2 && !out3) {
    return;
  }
  if (out0) {
    prg_276_from_rk_precomp_mode(rks[0], ctr16, ctr_tail4, use_ecb16, out0);
  }
  if (out1) {
    prg_276_from_rk_precomp_mode(rks[1], ctr16, ctr_tail4, use_ecb16, out1);
  }
  if (out2) {
    prg_276_from_rk_precomp_mode(rks[2], ctr16, ctr_tail4, use_ecb16, out2);
  }
  if (out3) {
    prg_276_from_rk_precomp_mode(rks[3], ctr16, ctr_tail4, use_ecb16, out3);
  }
}
#endif
#endif

static void prg_276(const uint8_t* key, const uint8_t* iv, uint32_t tweak, uint8_t* out) {
#if PRG_HAS_INTEL_SM4_NI
/* Native SM4 is preferred; packed schedules serve both PRG outputs. */
  if (prg_has_intel_sm4_ni_runtime_cached()) {
    uint32_t rk[SM4_KEY_SCHEDULE];
    intel_sm4_ni_expand_key1(key, rk);
    prg_intel_sm4_276_from_rk(rk, iv, tweak, out);
    return;
  }
#endif

#if PRG_HAS_HYGON_CIS_FASTPATH
  if (prg_has_hygon_cis_fastpath_runtime_cached()) {
    uint32_t rk[SM4_KEY_SCHEDULE];
    hygon_cis_sm4_set_key(key, rk);
    prg_hygon_276_from_rk(rk, iv, tweak, out);
    return;
  }
#endif

#if PRG_HAS_SM4_FASTPATH
  if (!prg_has_sm4_fastpath_runtime_cached()) {
    uint8_t internal_iv[PRG_BLOCK_SIZE];
    memcpy(internal_iv, iv, PRG_BLOCK_SIZE);
    add_to_upper_word(internal_iv, tweak);
    generic_prg(key, internal_iv, out, 128, PRG_276_BYTES);
    return;
  }

  uint32_t rk[SM4_KEY_SCHEDULE];
  prg_sm4_expand_key1(key, rk);
  prg_276_from_rk(rk, iv, tweak, out);
#else
  uint8_t internal_iv[PRG_BLOCK_SIZE];
  memcpy(internal_iv, iv, PRG_BLOCK_SIZE);
  add_to_upper_word(internal_iv, tweak);
  generic_prg(key, internal_iv, out, 128, PRG_276_BYTES);
#endif
}

static inline void prg_2lambda_and_276_single_impl(const uint8_t* key, const uint8_t* iv,
                                                   uint32_t tweak_2lambda, uint32_t tweak_276,
                                                   uint8_t* out2, uint8_t* out276,
                                                   unsigned int seclvl,
                                                   int use_sm4_fastpath) {
#if PRG_HAS_INTEL_SM4_NI
/* Native SM4 is preferred; packed schedules serve both PRG outputs. */
  if (seclvl == 128u && prg_has_intel_sm4_ni_runtime_cached()) {
    uint32_t rk[SM4_KEY_SCHEDULE];
    intel_sm4_ni_expand_key1(key, rk);
    prg_intel_sm4_ctr2_from_rk(rk, iv, tweak_2lambda, out2);
    prg_intel_sm4_276_from_rk(rk, iv, tweak_276, out276);
    return;
  }
#endif

#if PRG_HAS_HYGON_CIS_FASTPATH
  if (PRG_276_BYTES == PRG_HYGON_FUSED_276_BYTES && seclvl == 128u &&
      prg_has_hygon_cis_fastpath_runtime_cached()) {
    uint8_t ctr2[2 * PRG_BLOCK_SIZE];
    uint8_t prg276_ctr16[16 * PRG_BLOCK_SIZE];
    uint8_t prg276_ctr_tail4[4 * PRG_BLOCK_SIZE];
    prg_prepare_ctr2(iv, tweak_2lambda, ctr2);
    prg_prepare_counters_16_plus_tail4(iv, tweak_276, prg276_ctr16, prg276_ctr_tail4);
    prg_hygon_2lambda_276_from_key_precomp(key, ctr2, prg276_ctr16, prg276_ctr_tail4, out2,
                                           out276);
    return;
  }
#endif

#if PRG_HAS_SM4_FASTPATH
  if (use_sm4_fastpath && seclvl == 128u) {
    uint32_t rk[SM4_KEY_SCHEDULE];
    prg_sm4_expand_key1(key, rk);
    prg_sm4_ctr2_from_rk(rk, iv, tweak_2lambda, out2);
    prg_276_from_rk(rk, iv, tweak_276, out276);
    return;
  }
#endif
  prg_2_lambda_single_impl(key, iv, tweak_2lambda, out2, seclvl, use_sm4_fastpath);
  prg_276(key, iv, tweak_276, out276);
}

void prg_2_lambda_and_276_fixed_tweak_independent_batch_with_sd(
    const uint8_t* keys, size_t key_stride, const uint8_t* iv, uint32_t tweak_2lambda,
    uint32_t tweak_276, uint8_t* sd_out, size_t sd_stride, uint8_t* out_2lambda,
    size_t out_2lambda_stride, uint8_t* out_276, size_t out_276_stride, unsigned int seclvl,
    size_t count) {
  if (count == 0) {
    return;
  }

  const size_t lambda_bytes = seclvl / 8;

#if PRG_HAS_INTEL_SM4_NI
/* Native SM4 is preferred; packed schedules serve both PRG outputs. */
  if (prg_has_intel_sm4_ni_runtime_cached() && seclvl == 128u &&
      out_2lambda_stride == 32u && out_276_stride == PRG_276_BYTES) {
    size_t i = 0;
    while (i + 4u <= count) {
      intel_sm4_ni_rk4_packed rks;
      intel_sm4_ni_expand_key4_packed(keys + i * key_stride, (unsigned long)key_stride,
                                      &rks);
      for (size_t lane = 0; lane < 4u; ++lane) {
        const size_t idx = i + lane;
        const uint8_t* key_lane = keys + idx * key_stride;
        uint8_t* sd_lane = sd_out + idx * sd_stride;
        if (sd_lane != key_lane) {
          memcpy(sd_lane, key_lane, lambda_bytes);
        }
      }
      prg_intel_sm4_2lambda_batch4(
          &rks, iv, tweak_2lambda, out_2lambda + (i + 0u) * out_2lambda_stride,
          out_2lambda + (i + 1u) * out_2lambda_stride,
          out_2lambda + (i + 2u) * out_2lambda_stride,
          out_2lambda + (i + 3u) * out_2lambda_stride);
      prg_intel_sm4_276_batch4(
          &rks, iv, tweak_276, out_276 + (i + 0u) * out_276_stride,
          out_276 + (i + 1u) * out_276_stride, out_276 + (i + 2u) * out_276_stride,
          out_276 + (i + 3u) * out_276_stride);
      i += 4u;
    }
    for (; i < count; ++i) {
      uint32_t rk[SM4_KEY_SCHEDULE];
      const uint8_t* key_i = keys + i * key_stride;
      uint8_t* sd_i = sd_out + i * sd_stride;
      intel_sm4_ni_expand_key1(key_i, rk);
      if (sd_i != key_i) {
        memcpy(sd_i, key_i, lambda_bytes);
      }
      prg_intel_sm4_ctr2_from_rk(rk, iv, tweak_2lambda,
                                 out_2lambda + i * out_2lambda_stride);
      prg_intel_sm4_276_from_rk(rk, iv, tweak_276, out_276 + i * out_276_stride);
    }
    return;
  }
#endif

#if PRG_HAS_HYGON_CIS_FASTPATH
  if (PRG_276_BYTES == PRG_HYGON_FUSED_276_BYTES &&
      prg_has_hygon_cis_fastpath_runtime_cached() && seclvl == 128 &&
      out_2lambda_stride == 32 && out_276_stride == PRG_276_BYTES) {
    uint8_t ctr2[2 * PRG_BLOCK_SIZE];
    uint8_t prg276_ctr16[16 * PRG_BLOCK_SIZE];
    uint8_t prg276_ctr_tail4[4 * PRG_BLOCK_SIZE];

    prg_prepare_ctr2(iv, tweak_2lambda, ctr2);
    prg_prepare_counters_16_plus_tail4(iv, tweak_276, prg276_ctr16, prg276_ctr_tail4);

    size_t i = 0;
    while (count - i >= 8) {
      uint8_t* out276_ptrs[8] = {
          out_276 + (i + 0) * out_276_stride,
          out_276 + (i + 1) * out_276_stride,
          out_276 + (i + 2) * out_276_stride,
          out_276 + (i + 3) * out_276_stride,
          out_276 + (i + 4) * out_276_stride,
          out_276 + (i + 5) * out_276_stride,
          out_276 + (i + 6) * out_276_stride,
          out_276 + (i + 7) * out_276_stride,
      };

      for (size_t lane = 0; lane < 8; ++lane) {
        const size_t idx = i + lane;
        const uint8_t* key_lane = keys + idx * key_stride;
        uint8_t* sd_lane = sd_out + idx * sd_stride;
        if (sd_lane != key_lane) {
          memcpy(sd_lane, key_lane, lambda_bytes);
        }
      }

      hygon_cis_sm4_prg_2lambda_276_8way_from_key(
          keys + i * key_stride, key_stride, ctr2, out_2lambda + i * out_2lambda_stride,
          out_2lambda_stride, prg276_ctr16, prg276_ctr_tail4, out276_ptrs);
      i += 8;
    }

    while (count - i >= 4) {
      uint8_t* out276_ptrs[4] = {
          out_276 + (i + 0) * out_276_stride,
          out_276 + (i + 1) * out_276_stride,
          out_276 + (i + 2) * out_276_stride,
          out_276 + (i + 3) * out_276_stride,
      };

      for (size_t lane = 0; lane < 4; ++lane) {
        const size_t idx = i + lane;
        const uint8_t* key_lane = keys + idx * key_stride;
        uint8_t* sd_lane = sd_out + idx * sd_stride;
        if (sd_lane != key_lane) {
          memcpy(sd_lane, key_lane, lambda_bytes);
        }
      }

      hygon_cis_sm4_prg_2lambda_276_4way_from_key(
          keys + i * key_stride, key_stride, ctr2, out_2lambda + i * out_2lambda_stride,
          out_2lambda_stride, prg276_ctr16, prg276_ctr_tail4, out276_ptrs);
      i += 4;
    }

    for (; i < count; ++i) {
      const uint8_t* key_i = keys + i * key_stride;
      uint8_t* sd_i = sd_out + i * sd_stride;
      uint8_t* out2_i = out_2lambda + i * out_2lambda_stride;
      uint8_t* out276_i = out_276 + i * out_276_stride;
      if (sd_i != key_i) {
        memcpy(sd_i, key_i, lambda_bytes);
      }
      prg_hygon_2lambda_276_from_key_precomp(key_i, ctr2, prg276_ctr16, prg276_ctr_tail4,
                                             out2_i, out276_i);
    }
    return;
  }
#endif

#if PRG_HAS_SM4_FASTPATH
  if (prg_has_sm4_fastpath_runtime_cached() && seclvl == 128 && out_2lambda_stride == 32 &&
      out_276_stride == PRG_276_BYTES) {
    const int use_sm4_fvl = sm4th_x86_has_avx512f_vl();
    const int use_prg276_ecb16 = (sm4_aesni_avx2_asm_ecb_enc_blk_16 != NULL) && sm4th_x86_has_avx2();
    uint8_t prg276_ctr16[16 * PRG_BLOCK_SIZE];
    uint8_t prg276_ctr_tail4[4 * PRG_BLOCK_SIZE];
    uint8_t ctr0[4 * PRG_BLOCK_SIZE];
    uint8_t ctr1[4 * PRG_BLOCK_SIZE];

    prg_prepare_counters_16_plus_tail4(iv, tweak_276, prg276_ctr16, prg276_ctr_tail4);

    for (size_t lane = 0; lane < 4; ++lane) {
      uint8_t* ctr0_lane = ctr0 + lane * PRG_BLOCK_SIZE;
      uint8_t* ctr1_lane = ctr1 + lane * PRG_BLOCK_SIZE;
      memcpy(ctr0_lane, iv, PRG_BLOCK_SIZE);
      add_to_upper_word(ctr0_lane, tweak_2lambda);
      memcpy(ctr1_lane, ctr0_lane, PRG_BLOCK_SIZE);
      prg_increment_iv(ctr1_lane);
    }

    size_t i = 0;
    while (i + 4 <= count) {
      uint32_t rks[4][SM4_KEY_SCHEDULE];
      uint8_t enc0[4 * PRG_BLOCK_SIZE];
      uint8_t enc1[4 * PRG_BLOCK_SIZE];

      if (use_sm4_fvl) {
        sm4_key_schedule_interleaved_4_avx512(keys + i * key_stride, key_stride, rks);
      } else {
        sm4_key_schedule_interleaved_4(keys + i * key_stride, key_stride, rks);
      }

#if defined(__x86_64__) || defined(__i386__)
      if (use_sm4_fvl) {
        sm4_encrypt4_diffkeys_1blk_avx512(rks, ctr0, enc0);
        sm4_encrypt4_diffkeys_1blk_avx512(rks, ctr1, enc1);
      } else {
        sm4_encrypt4_diffkeys_1blk(rks, ctr0, enc0);
        sm4_encrypt4_diffkeys_1blk(rks, ctr1, enc1);
      }
      for (size_t lane = 0; lane < 4; ++lane) {
        const size_t idx = i + lane;
        const uint8_t* key_lane = keys + idx * key_stride;
        uint8_t* sd_lane = sd_out + idx * sd_stride;
        uint8_t* out2_lane = out_2lambda + idx * out_2lambda_stride;
        if (sd_lane != key_lane) {
          memcpy(sd_lane, key_lane, lambda_bytes);
        }
        memcpy(out2_lane, enc0 + lane * PRG_BLOCK_SIZE, PRG_BLOCK_SIZE);
        memcpy(out2_lane + PRG_BLOCK_SIZE, enc1 + lane * PRG_BLOCK_SIZE, PRG_BLOCK_SIZE);
      }
      prg_276_batch4_generate_precomp_mode(
          rks, prg276_ctr16, prg276_ctr_tail4, use_prg276_ecb16,
          out_276 + (i + 0) * out_276_stride, out_276 + (i + 1) * out_276_stride,
          out_276 + (i + 2) * out_276_stride, out_276 + (i + 3) * out_276_stride);
#else
      for (size_t lane = 0; lane < 4; ++lane) {
        const size_t idx = i + lane;
        const uint8_t* key_lane = keys + idx * key_stride;
        uint8_t* sd_lane = sd_out + idx * sd_stride;
        uint8_t* out2_lane = out_2lambda + idx * out_2lambda_stride;
        uint8_t* out276_lane = out_276 + idx * out_276_stride;
        if (sd_lane != key_lane) {
          memcpy(sd_lane, key_lane, lambda_bytes);
        }
        prg_sm4_ctr2_from_rk(rks[lane], iv, tweak_2lambda, out2_lane);
        prg_276_from_rk(rks[lane], iv, tweak_276, out276_lane);
      }
#endif
      i += 4;
    }

    for (; i < count; ++i) {
      uint32_t rk[SM4_KEY_SCHEDULE];
      const uint8_t* key_i = keys + i * key_stride;
      uint8_t* sd_i = sd_out + i * sd_stride;
      uint8_t* out2_i = out_2lambda + i * out_2lambda_stride;
      uint8_t* out276_i = out_276 + i * out_276_stride;
      prg_sm4_expand_key1(key_i, rk);
      if (sd_i != key_i) {
        memcpy(sd_i, key_i, lambda_bytes);
      }
      prg_sm4_ctr2_from_rk(rk, iv, tweak_2lambda, out2_i);
      prg_276_from_rk_precomp_mode(rk, prg276_ctr16, prg276_ctr_tail4, use_prg276_ecb16,
                                   out276_i);
    }
    return;
  }
#endif

  const int use_sm4_fastpath = (seclvl == 128) && prg_has_sm4_fastpath_runtime_cached();
  for (size_t i = 0; i < count; ++i) {
    const uint8_t* key_i = keys + i * key_stride;
    uint8_t* sd_i = sd_out + i * sd_stride;
    uint8_t* out2_i = out_2lambda + i * out_2lambda_stride;
    uint8_t* out276_i = out_276 + i * out_276_stride;
    if (sd_i != key_i) {
      memcpy(sd_i, key_i, lambda_bytes);
    }
    prg_2lambda_and_276_single_impl(key_i, iv, tweak_2lambda, tweak_276, out2_i, out276_i,
                                    seclvl, use_sm4_fastpath);
  }
}

void prg_2_lambda_and_276_fixed_tweak_independent_batch_with_sd_xor_map(
    const uint8_t* keys, size_t key_stride, const uint8_t* iv, uint32_t tweak_2lambda,
    uint32_t tweak_276, uint8_t* sd_out, size_t sd_stride, size_t sd_index_base,
    size_t sd_index_xor, uint8_t* out_2lambda, size_t out_2lambda_stride, uint8_t* out_276,
    size_t out_276_stride, unsigned int seclvl, size_t count) {
  if (count == 0) {
    return;
  }

  const size_t lambda_bytes = seclvl / 8;

#if PRG_HAS_INTEL_SM4_NI
/* Native SM4 is preferred; packed schedules serve both PRG outputs. */
  if (prg_has_intel_sm4_ni_runtime_cached() && seclvl == 128u &&
      out_2lambda_stride == 32u && out_276_stride == PRG_276_BYTES) {
    size_t i = 0;
    while (i + 4u <= count) {
      intel_sm4_ni_rk4_packed rks;
      uint8_t* out276_ptr[4];
      uint8_t scratch276[4][PRG_276_BYTES];
      intel_sm4_ni_expand_key4_packed(keys + i * key_stride, (unsigned long)key_stride,
                                      &rks);
      for (size_t lane = 0; lane < 4u; ++lane) {
        const size_t idx = i + lane;
        uint8_t* sd_lane =
            prg_sd_xor_map_slot(sd_out, sd_stride, idx, sd_index_base, sd_index_xor);
        out276_ptr[lane] =
            prg_sd_xor_map_slot(out_276, out_276_stride, idx, sd_index_base, sd_index_xor);
        if (sd_lane) {
          memcpy(sd_lane, keys + idx * key_stride, lambda_bytes);
        }
      }
      prg_intel_sm4_2lambda_batch4(
          &rks, iv, tweak_2lambda, out_2lambda + (i + 0u) * out_2lambda_stride,
          out_2lambda + (i + 1u) * out_2lambda_stride,
          out_2lambda + (i + 2u) * out_2lambda_stride,
          out_2lambda + (i + 3u) * out_2lambda_stride);
      for (size_t lane = 0; lane < 4u; ++lane) {
        if (!out276_ptr[lane]) {
          out276_ptr[lane] = scratch276[lane];
        }
      }
      prg_intel_sm4_276_batch4(&rks, iv, tweak_276, out276_ptr[0], out276_ptr[1],
                               out276_ptr[2], out276_ptr[3]);
      i += 4u;
    }
    for (; i < count; ++i) {
      uint32_t rk[SM4_KEY_SCHEDULE];
      const uint8_t* key_i = keys + i * key_stride;
      uint8_t* sd_i =
          prg_sd_xor_map_slot(sd_out, sd_stride, i, sd_index_base, sd_index_xor);
      uint8_t* out276_i =
          prg_sd_xor_map_slot(out_276, out_276_stride, i, sd_index_base, sd_index_xor);
      intel_sm4_ni_expand_key1(key_i, rk);
      if (sd_i) {
        memcpy(sd_i, key_i, lambda_bytes);
      }
      prg_intel_sm4_ctr2_from_rk(rk, iv, tweak_2lambda,
                                 out_2lambda + i * out_2lambda_stride);
      if (out276_i) {
        prg_intel_sm4_276_from_rk(rk, iv, tweak_276, out276_i);
      }
    }
    return;
  }
#endif

#if PRG_HAS_HYGON_CIS_FASTPATH
  if (PRG_276_BYTES == PRG_HYGON_FUSED_276_BYTES &&
      prg_has_hygon_cis_fastpath_runtime_cached() && seclvl == 128 &&
      out_2lambda_stride == 32 && out_276_stride == PRG_276_BYTES) {
    uint8_t ctr2[2 * PRG_BLOCK_SIZE];
    uint8_t prg276_ctr16[16 * PRG_BLOCK_SIZE];
    uint8_t prg276_ctr_tail4[4 * PRG_BLOCK_SIZE];

    prg_prepare_ctr2(iv, tweak_2lambda, ctr2);
    prg_prepare_counters_16_plus_tail4(iv, tweak_276, prg276_ctr16, prg276_ctr_tail4);

    size_t i = 0;
    while (count - i >= 8) {
      uint8_t* sd_ptrs[8];
      uint8_t* out276_ptrs[8];
      int have_all_out276 = 1;

      for (size_t lane = 0; lane < 8; ++lane) {
        const size_t idx = i + lane;
        sd_ptrs[lane] = prg_sd_xor_map_slot(sd_out, sd_stride, idx, sd_index_base, sd_index_xor);
        out276_ptrs[lane] =
            prg_sd_xor_map_slot(out_276, out_276_stride, idx, sd_index_base, sd_index_xor);
        if (!out276_ptrs[lane]) {
          have_all_out276 = 0;
        }
      }

      if (have_all_out276) {
        for (size_t lane = 0; lane < 8; ++lane) {
          if (sd_ptrs[lane]) {
            memcpy(sd_ptrs[lane], keys + (i + lane) * key_stride, lambda_bytes);
          }
        }
        hygon_cis_sm4_prg_2lambda_276_8way_from_key(
            keys + i * key_stride, key_stride, ctr2, out_2lambda + i * out_2lambda_stride,
            out_2lambda_stride, prg276_ctr16, prg276_ctr_tail4, out276_ptrs);
        i += 8;
        continue;
      }

      for (size_t lane = 0; lane < 8; ++lane) {
        const size_t idx = i + lane;
        const uint8_t* key_i = keys + idx * key_stride;
        uint8_t* out2_i = out_2lambda + idx * out_2lambda_stride;
        if (sd_ptrs[lane]) {
          memcpy(sd_ptrs[lane], key_i, lambda_bytes);
        }
        if (out276_ptrs[lane]) {
          prg_hygon_2lambda_276_from_key_precomp(key_i, ctr2, prg276_ctr16, prg276_ctr_tail4,
                                                 out2_i, out276_ptrs[lane]);
        } else {
          hygon_cis_sm4_prg_2lambda_from_key(key_i, ctr2, out2_i);
        }
      }
      i += 8;
    }

    while (count - i >= 4) {
      uint8_t* sd_ptrs[4];
      uint8_t* out276_ptrs[4];
      int have_all_out276 = 1;

      for (size_t lane = 0; lane < 4; ++lane) {
        const size_t idx = i + lane;
        sd_ptrs[lane] = prg_sd_xor_map_slot(sd_out, sd_stride, idx, sd_index_base, sd_index_xor);
        out276_ptrs[lane] =
            prg_sd_xor_map_slot(out_276, out_276_stride, idx, sd_index_base, sd_index_xor);
        if (!out276_ptrs[lane]) {
          have_all_out276 = 0;
        }
      }

      if (have_all_out276) {
        for (size_t lane = 0; lane < 4; ++lane) {
          if (sd_ptrs[lane]) {
            memcpy(sd_ptrs[lane], keys + (i + lane) * key_stride, lambda_bytes);
          }
        }
        hygon_cis_sm4_prg_2lambda_276_4way_from_key(
            keys + i * key_stride, key_stride, ctr2, out_2lambda + i * out_2lambda_stride,
            out_2lambda_stride, prg276_ctr16, prg276_ctr_tail4, out276_ptrs);
        i += 4;
        continue;
      }

      for (size_t lane = 0; lane < 4; ++lane) {
        const size_t idx = i + lane;
        const uint8_t* key_i = keys + idx * key_stride;
        uint8_t* out2_i = out_2lambda + idx * out_2lambda_stride;
        if (sd_ptrs[lane]) {
          memcpy(sd_ptrs[lane], key_i, lambda_bytes);
        }
        if (out276_ptrs[lane]) {
          prg_hygon_2lambda_276_from_key_precomp(key_i, ctr2, prg276_ctr16, prg276_ctr_tail4,
                                                 out2_i, out276_ptrs[lane]);
        } else {
          hygon_cis_sm4_prg_2lambda_from_key(key_i, ctr2, out2_i);
        }
      }
      i += 4;
    }

    for (; i < count; ++i) {
      const uint8_t* key_i = keys + i * key_stride;
      uint8_t* out2_i = out_2lambda + i * out_2lambda_stride;
      uint8_t* sd_i =
          prg_sd_xor_map_slot(sd_out, sd_stride, i, sd_index_base, sd_index_xor);
      uint8_t* out276_i =
          prg_sd_xor_map_slot(out_276, out_276_stride, i, sd_index_base, sd_index_xor);

      if (sd_i) {
        memcpy(sd_i, key_i, lambda_bytes);
      }
      if (out276_i) {
        prg_hygon_2lambda_276_from_key_precomp(key_i, ctr2, prg276_ctr16, prg276_ctr_tail4,
                                               out2_i, out276_i);
      } else {
        hygon_cis_sm4_prg_2lambda_from_key(key_i, ctr2, out2_i);
      }
    }
    return;
  }
#endif

#if PRG_HAS_SM4_FASTPATH
  if (prg_has_sm4_fastpath_runtime_cached() && seclvl == 128 && out_2lambda_stride == 32 &&
      out_276_stride == PRG_276_BYTES) {
    const int use_sm4_fvl = sm4th_x86_has_avx512f_vl();
    const int use_prg276_ecb16 = (sm4_aesni_avx2_asm_ecb_enc_blk_16 != NULL) && sm4th_x86_has_avx2();
    uint8_t prg276_ctr16[16 * PRG_BLOCK_SIZE];
    uint8_t prg276_ctr_tail4[4 * PRG_BLOCK_SIZE];
    uint8_t ctr0[4 * PRG_BLOCK_SIZE];
    uint8_t ctr1[4 * PRG_BLOCK_SIZE];

    prg_prepare_counters_16_plus_tail4(iv, tweak_276, prg276_ctr16, prg276_ctr_tail4);

    for (size_t lane = 0; lane < 4; ++lane) {
      uint8_t* ctr0_lane = ctr0 + lane * PRG_BLOCK_SIZE;
      uint8_t* ctr1_lane = ctr1 + lane * PRG_BLOCK_SIZE;
      memcpy(ctr0_lane, iv, PRG_BLOCK_SIZE);
      add_to_upper_word(ctr0_lane, tweak_2lambda);
      memcpy(ctr1_lane, ctr0_lane, PRG_BLOCK_SIZE);
      prg_increment_iv(ctr1_lane);
    }

    size_t i = 0;
    while (i + 4 <= count) {
      uint32_t rks[4][SM4_KEY_SCHEDULE];
      uint8_t enc0[4 * PRG_BLOCK_SIZE];
      uint8_t enc1[4 * PRG_BLOCK_SIZE];

      if (use_sm4_fvl) {
        sm4_key_schedule_interleaved_4_avx512(keys + i * key_stride, key_stride, rks);
      } else {
        sm4_key_schedule_interleaved_4(keys + i * key_stride, key_stride, rks);
      }

#if defined(__x86_64__) || defined(__i386__)
      if (use_sm4_fvl) {
        sm4_encrypt4_diffkeys_1blk_avx512(rks, ctr0, enc0);
        sm4_encrypt4_diffkeys_1blk_avx512(rks, ctr1, enc1);
      } else {
        sm4_encrypt4_diffkeys_1blk(rks, ctr0, enc0);
        sm4_encrypt4_diffkeys_1blk(rks, ctr1, enc1);
      }
      uint8_t* out276_0 =
          prg_sd_xor_map_slot(out_276, out_276_stride, i + 0, sd_index_base, sd_index_xor);
      uint8_t* out276_1 =
          prg_sd_xor_map_slot(out_276, out_276_stride, i + 1, sd_index_base, sd_index_xor);
      uint8_t* out276_2 =
          prg_sd_xor_map_slot(out_276, out_276_stride, i + 2, sd_index_base, sd_index_xor);
      uint8_t* out276_3 =
          prg_sd_xor_map_slot(out_276, out_276_stride, i + 3, sd_index_base, sd_index_xor);

      for (size_t lane = 0; lane < 4; ++lane) {
        const size_t idx = i + lane;
        const uint8_t* key_lane = keys + idx * key_stride;
        uint8_t* out2_lane = out_2lambda + idx * out_2lambda_stride;
        uint8_t* sd_lane =
            prg_sd_xor_map_slot(sd_out, sd_stride, idx, sd_index_base, sd_index_xor);
        if (sd_lane) {
          memcpy(sd_lane, key_lane, lambda_bytes);
        }
        memcpy(out2_lane, enc0 + lane * PRG_BLOCK_SIZE, PRG_BLOCK_SIZE);
        memcpy(out2_lane + PRG_BLOCK_SIZE, enc1 + lane * PRG_BLOCK_SIZE, PRG_BLOCK_SIZE);
      }

      if (out276_0 || out276_1 || out276_2 || out276_3) {
        prg_276_batch4_generate_precomp_mode(rks, prg276_ctr16, prg276_ctr_tail4,
                                             use_prg276_ecb16, out276_0, out276_1, out276_2,
                                             out276_3);
      }
#else
      for (size_t lane = 0; lane < 4; ++lane) {
        const size_t idx = i + lane;
        const uint8_t* key_lane = keys + idx * key_stride;
        uint8_t* out2_lane = out_2lambda + idx * out_2lambda_stride;
        uint8_t* sd_lane =
            prg_sd_xor_map_slot(sd_out, sd_stride, idx, sd_index_base, sd_index_xor);
        uint8_t* out276_lane =
            prg_sd_xor_map_slot(out_276, out_276_stride, idx, sd_index_base, sd_index_xor);
        if (sd_lane) {
          memcpy(sd_lane, key_lane, lambda_bytes);
        }
        prg_sm4_ctr2_from_rk(rks[lane], iv, tweak_2lambda, out2_lane);
        if (out276_lane) {
          prg_276_from_rk(rks[lane], iv, tweak_276, out276_lane);
        }
      }
#endif
      i += 4;
    }

    for (; i < count; ++i) {
      uint32_t rk[SM4_KEY_SCHEDULE];
      const uint8_t* key_i = keys + i * key_stride;
      uint8_t* out2_i = out_2lambda + i * out_2lambda_stride;
      uint8_t* sd_i =
          prg_sd_xor_map_slot(sd_out, sd_stride, i, sd_index_base, sd_index_xor);
      uint8_t* out276_i =
          prg_sd_xor_map_slot(out_276, out_276_stride, i, sd_index_base, sd_index_xor);
      prg_sm4_expand_key1(key_i, rk);
      if (sd_i) {
        memcpy(sd_i, key_i, lambda_bytes);
      }
      prg_sm4_ctr2_from_rk(rk, iv, tweak_2lambda, out2_i);
      if (out276_i) {
        prg_276_from_rk_precomp_mode(rk, prg276_ctr16, prg276_ctr_tail4, use_prg276_ecb16,
                                     out276_i);
      }
    }
    return;
  }
#endif

  const int use_sm4_fastpath = (seclvl == 128) && prg_has_sm4_fastpath_runtime_cached();
  for (size_t i = 0; i < count; ++i) {
    const uint8_t* key_i = keys + i * key_stride;
    uint8_t* out2_i = out_2lambda + i * out_2lambda_stride;
    uint8_t* sd_i =
        prg_sd_xor_map_slot(sd_out, sd_stride, i, sd_index_base, sd_index_xor);
    uint8_t* out276_i =
        prg_sd_xor_map_slot(out_276, out_276_stride, i, sd_index_base, sd_index_xor);
    if (sd_i) {
      memcpy(sd_i, key_i, lambda_bytes);
    }
    if (out276_i) {
      prg_2lambda_and_276_single_impl(key_i, iv, tweak_2lambda, tweak_276, out2_i, out276_i,
                                      seclvl, use_sm4_fastpath);
    } else {
      prg_2_lambda_single_impl(key_i, iv, tweak_2lambda, out2_i, seclvl, use_sm4_fastpath);
    }
  }
}
