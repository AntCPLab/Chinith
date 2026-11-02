/*
* SM4-ECB PRG wrapper implementation, obtained from sm4th
*/

#include "sm4.h"
#include "compat.h"
#include "x86_caps.h"
//#include <time.h>
#include <string.h>

#ifndef SM4TH_ENABLE_HYGON_CIS
#define SM4TH_ENABLE_HYGON_CIS 0
#endif

#if SM4TH_ENABLE_HYGON_CIS && defined(__x86_64__)
#include "hygon_cis_sm4.h"
#endif

#ifndef PRG_BLOCK_SIZE
#define PRG_BLOCK_SIZE SM4_BLOCK_SIZE
#endif

#if defined(__x86_64__) || defined(__i386__)
#include <x86intrin.h>
#endif

/* Native VSM4 kernels adapted from origin/JoCR; keep ISA local. */
#if SM4TH_NATIVE_SM4_COMPILED
#include <immintrin.h>
#define SM4_NI_TARGET __attribute__((target("avx2,sm4")))
static const uint32_t native_sm4_fk[4] = {
    0xa3b1bac6u, 0x56aa3350u, 0x677d9197u, 0xb27022dcu};

static const uint32_t native_sm4_ck[32] = {
    0x00070e15u, 0x1c232a31u, 0x383f464du, 0x545b6269u,
    0x70777e85u, 0x8c939aa1u, 0xa8afb6bdu, 0xc4cbd2d9u,
    0xe0e7eef5u, 0xfc030a11u, 0x181f262du, 0x343b4249u,
    0x50575e65u, 0x6c737a81u, 0x888f969du, 0xa4abb2b9u,
    0xc0c7ced5u, 0xdce3eaf1u, 0xf8ff060du, 0x141b2229u,
    0x30373e45u, 0x4c535a61u, 0x686f767du, 0x848b9299u,
    0xa0a7aeb5u, 0xbcc3cad1u, 0xd8dfe6edu, 0xf4fb0209u,
    0x10171e25u, 0x2c333a41u, 0x484f565du, 0x646b7279u};

static inline uint32_t native_load_be32(const uint8_t p[4]) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
         ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static inline void native_store_be32(uint8_t p[4], uint32_t x) {
  p[0] = (uint8_t)(x >> 24);
  p[1] = (uint8_t)(x >> 16);
  p[2] = (uint8_t)(x >> 8);
  p[3] = (uint8_t)x;
}

static inline __m128i SM4_NI_TARGET native_load_block(const uint8_t in[16]) {
  return _mm_setr_epi32((int)native_load_be32(in + 0), (int)native_load_be32(in + 4),
                        (int)native_load_be32(in + 8), (int)native_load_be32(in + 12));
}

static inline void SM4_NI_TARGET native_store_block(uint8_t out[16], __m128i state) {
  uint32_t words[4];
  _mm_storeu_si128((__m128i*)(void*)words, state);
  native_store_be32(out + 0, words[3]);
  native_store_be32(out + 4, words[2]);
  native_store_be32(out + 8, words[1]);
  native_store_be32(out + 12, words[0]);
}

static inline __m256i SM4_NI_TARGET native_pack2(__m128i lo, __m128i hi) {
  return _mm256_inserti128_si256(_mm256_castsi128_si256(lo), hi, 1);
}

static inline __m256i SM4_NI_TARGET native_load_rk_packed(const uint32_t rk[8]) {
  return _mm256_loadu_si256((const __m256i*)(const void*)rk);
}

static void SM4_NI_TARGET native_expand_key1_impl(const uint8_t key[16], uint32_t rk[32]) {
  __m128i state = _mm_setr_epi32(
      (int)(native_load_be32(key + 0) ^ native_sm4_fk[0]),
      (int)(native_load_be32(key + 4) ^ native_sm4_fk[1]),
      (int)(native_load_be32(key + 8) ^ native_sm4_fk[2]),
      (int)(native_load_be32(key + 12) ^ native_sm4_fk[3]));
  for (int group = 0; group < 8; ++group) {
    const __m128i ck = _mm_loadu_si128(
        (const __m128i*)(const void*)(native_sm4_ck + group * 4));
    state = _mm_sm4key4_epi32(state, ck);
    _mm_storeu_si128((__m128i*)(void*)(rk + group * 4), state);
  }
}

static void SM4_NI_TARGET native_expand_key4_impl(const uint8_t* keys, unsigned long stride,
                                            uint32_t rk[4][32]) {
  __m128i state128[4];
  for (int lane = 0; lane < 4; ++lane) {
    const uint8_t* key = keys + (unsigned long)lane * stride;
    state128[lane] = _mm_setr_epi32(
        (int)(native_load_be32(key + 0) ^ native_sm4_fk[0]),
        (int)(native_load_be32(key + 4) ^ native_sm4_fk[1]),
        (int)(native_load_be32(key + 8) ^ native_sm4_fk[2]),
        (int)(native_load_be32(key + 12) ^ native_sm4_fk[3]));
  }
  __m256i state01 = native_pack2(state128[0], state128[1]);
  __m256i state23 = native_pack2(state128[2], state128[3]);
  for (int group = 0; group < 8; ++group) {
    const __m128i ck128 = _mm_loadu_si128(
        (const __m128i*)(const void*)(native_sm4_ck + group * 4));
    const __m256i ck = _mm256_broadcastsi128_si256(ck128);
    state01 = _mm256_sm4key4_epi32(state01, ck);
    state23 = _mm256_sm4key4_epi32(state23, ck);
    _mm_storeu_si128((__m128i*)(void*)(rk[0] + group * 4),
                     _mm256_castsi256_si128(state01));
    _mm_storeu_si128((__m128i*)(void*)(rk[1] + group * 4),
                     _mm256_extracti128_si256(state01, 1));
    _mm_storeu_si128((__m128i*)(void*)(rk[2] + group * 4),
                     _mm256_castsi256_si128(state23));
    _mm_storeu_si128((__m128i*)(void*)(rk[3] + group * 4),
                     _mm256_extracti128_si256(state23, 1));
  }
}

static void SM4_NI_TARGET native_expand_key4_packed_impl(
    const uint8_t* keys, unsigned long stride, intel_sm4_ni_rk4_packed* rk) {
  __m128i state128[4];
  for (int lane = 0; lane < 4; ++lane) {
    const uint8_t* key = keys + (unsigned long)lane * stride;
    state128[lane] = _mm_setr_epi32(
        (int)(native_load_be32(key + 0) ^ native_sm4_fk[0]),
        (int)(native_load_be32(key + 4) ^ native_sm4_fk[1]),
        (int)(native_load_be32(key + 8) ^ native_sm4_fk[2]),
        (int)(native_load_be32(key + 12) ^ native_sm4_fk[3]));
  }
  __m256i state01 = native_pack2(state128[0], state128[1]);
  __m256i state23 = native_pack2(state128[2], state128[3]);
  for (int group = 0; group < INTEL_SM4_RK_GROUPS; ++group) {
    const __m128i ck128 = _mm_loadu_si128(
        (const __m128i*)(const void*)(native_sm4_ck + group * 4));
    const __m256i ck = _mm256_broadcastsi128_si256(ck128);
    state01 = _mm256_sm4key4_epi32(state01, ck);
    state23 = _mm256_sm4key4_epi32(state23, ck);
    _mm256_storeu_si256((__m256i*)(void*)rk->pair01[group], state01);
    _mm256_storeu_si256((__m256i*)(void*)rk->pair23[group], state23);
  }
}

static inline __m128i SM4_NI_TARGET native_encrypt_xmm(__m128i state, const uint32_t rk[32]) {
  for (int group = 0; group < 8; ++group) {
    const __m128i key = _mm_loadu_si128(
        (const __m128i*)(const void*)(rk + group * 4));
    state = _mm_sm4rnds4_epi32(state, key);
  }
  return state;
}

static void SM4_NI_TARGET native_encrypt1_impl(const uint32_t rk[32], const uint8_t in[16],
                                        uint8_t out[16]) {
  native_store_block(out, native_encrypt_xmm(native_load_block(in), rk));
}

static void SM4_NI_TARGET native_encrypt2_same_key_impl(const uint32_t rk[32],
                                                  const uint8_t in[2][16],
                                                  uint8_t out[2][16]) {
  __m256i state = native_pack2(native_load_block(in[0]), native_load_block(in[1]));
  for (int group = 0; group < 8; ++group) {
    const __m128i key128 = _mm_loadu_si128(
        (const __m128i*)(const void*)(rk + group * 4));
    state = _mm256_sm4rnds4_epi32(state, _mm256_broadcastsi128_si256(key128));
  }
  native_store_block(out[0], _mm256_castsi256_si128(state));
  native_store_block(out[1], _mm256_extracti128_si256(state, 1));
}

static void SM4_NI_TARGET native_encrypt4_keys_2blocks_packed_impl(
    const intel_sm4_ni_rk4_packed* rk, const uint8_t in[2][16],
    uint8_t* out0, uint8_t* out1, uint8_t* out2, uint8_t* out3) {
  const __m128i block0 = native_load_block(in[0]);
  const __m128i block1 = native_load_block(in[1]);
  __m256i state0_01 = native_pack2(block0, block0);
  __m256i state0_23 = native_pack2(block0, block0);
  __m256i state1_01 = native_pack2(block1, block1);
  __m256i state1_23 = native_pack2(block1, block1);
  for (int group = 0; group < INTEL_SM4_RK_GROUPS; ++group) {
    const __m256i rk01 = native_load_rk_packed(rk->pair01[group]);
    const __m256i rk23 = native_load_rk_packed(rk->pair23[group]);
    state0_01 = _mm256_sm4rnds4_epi32(state0_01, rk01);
    state0_23 = _mm256_sm4rnds4_epi32(state0_23, rk23);
    state1_01 = _mm256_sm4rnds4_epi32(state1_01, rk01);
    state1_23 = _mm256_sm4rnds4_epi32(state1_23, rk23);
  }
  native_store_block(out0, _mm256_castsi256_si128(state0_01));
  native_store_block(out1, _mm256_extracti128_si256(state0_01, 1));
  native_store_block(out2, _mm256_castsi256_si128(state0_23));
  native_store_block(out3, _mm256_extracti128_si256(state0_23, 1));
  native_store_block(out0 + 16, _mm256_castsi256_si128(state1_01));
  native_store_block(out1 + 16, _mm256_extracti128_si256(state1_01, 1));
  native_store_block(out2 + 16, _mm256_castsi256_si128(state1_23));
  native_store_block(out3 + 16, _mm256_extracti128_si256(state1_23, 1));
}

static void SM4_NI_TARGET native_encrypt4_keys_6blocks_packed_impl(
    const intel_sm4_ni_rk4_packed* rk, const uint8_t in[6][16],
    uint8_t* out0, uint8_t* out1, uint8_t* out2, uint8_t* out3) {
  const __m128i b0 = native_load_block(in[0]);
  const __m128i b1 = native_load_block(in[1]);
  const __m128i b2 = native_load_block(in[2]);
  const __m128i b3 = native_load_block(in[3]);
  const __m128i b4 = native_load_block(in[4]);
  const __m128i b5 = native_load_block(in[5]);
  __m256i s01_0 = native_pack2(b0, b0), s23_0 = native_pack2(b0, b0);
  __m256i s01_1 = native_pack2(b1, b1), s23_1 = native_pack2(b1, b1);
  __m256i s01_2 = native_pack2(b2, b2), s23_2 = native_pack2(b2, b2);
  __m256i s01_3 = native_pack2(b3, b3), s23_3 = native_pack2(b3, b3);
  __m256i s01_4 = native_pack2(b4, b4), s23_4 = native_pack2(b4, b4);
  __m256i s01_5 = native_pack2(b5, b5), s23_5 = native_pack2(b5, b5);
  for (int group = 0; group < INTEL_SM4_RK_GROUPS; ++group) {
    const __m256i rk01 = native_load_rk_packed(rk->pair01[group]);
    const __m256i rk23 = native_load_rk_packed(rk->pair23[group]);
    s01_0 = _mm256_sm4rnds4_epi32(s01_0, rk01);
    s23_0 = _mm256_sm4rnds4_epi32(s23_0, rk23);
    s01_1 = _mm256_sm4rnds4_epi32(s01_1, rk01);
    s23_1 = _mm256_sm4rnds4_epi32(s23_1, rk23);
    s01_2 = _mm256_sm4rnds4_epi32(s01_2, rk01);
    s23_2 = _mm256_sm4rnds4_epi32(s23_2, rk23);
    s01_3 = _mm256_sm4rnds4_epi32(s01_3, rk01);
    s23_3 = _mm256_sm4rnds4_epi32(s23_3, rk23);
    s01_4 = _mm256_sm4rnds4_epi32(s01_4, rk01);
    s23_4 = _mm256_sm4rnds4_epi32(s23_4, rk23);
    s01_5 = _mm256_sm4rnds4_epi32(s01_5, rk01);
    s23_5 = _mm256_sm4rnds4_epi32(s23_5, rk23);
  }
#define STORE6(BLOCK, S01, S23)                                                \
  do {                                                                         \
    native_store_block(out0 + (BLOCK) * 16, _mm256_castsi256_si128(S01));             \
    native_store_block(out1 + (BLOCK) * 16, _mm256_extracti128_si256((S01), 1));       \
    native_store_block(out2 + (BLOCK) * 16, _mm256_castsi256_si128(S23));             \
    native_store_block(out3 + (BLOCK) * 16, _mm256_extracti128_si256((S23), 1));       \
  } while (0)
  STORE6(0, s01_0, s23_0);
  STORE6(1, s01_1, s23_1);
  STORE6(2, s01_2, s23_2);
  STORE6(3, s01_3, s23_3);
  STORE6(4, s01_4, s23_4);
  STORE6(5, s01_5, s23_5);
#undef STORE6
}

void intel_sm4_ni_expand_key1(const uint8_t key[16], uint32_t rk[32]) {
  native_expand_key1_impl(key, rk);

}

void intel_sm4_ni_encrypt1(const uint32_t rk[32], const uint8_t in[16], uint8_t out[16]) {
  native_encrypt1_impl(rk, in, out);

}

void intel_sm4_ni_encrypt2_same_key(const uint32_t rk[32], const uint8_t in[2][16],
                                    uint8_t out[2][16]) {
  native_encrypt2_same_key_impl(rk, in, out);

}

void intel_sm4_ni_expand_key4(const uint8_t* keys, unsigned long key_stride,
                              uint32_t rk[4][32]) {
  native_expand_key4_impl(keys, key_stride, rk);

}

void intel_sm4_ni_expand_key4_packed(const uint8_t* keys, unsigned long key_stride,
                                     intel_sm4_ni_rk4_packed* rk) {
  native_expand_key4_packed_impl(keys, key_stride, rk);

}

void intel_sm4_ni_encrypt4_keys_2blocks_packed(
    const intel_sm4_ni_rk4_packed* rk, const uint8_t in[2][16],
    uint8_t* out0, uint8_t* out1, uint8_t* out2, uint8_t* out3) {
  native_encrypt4_keys_2blocks_packed_impl(rk, in, out0, out1, out2, out3);

}

void intel_sm4_ni_encrypt4_keys_6blocks_packed(
    const intel_sm4_ni_rk4_packed* rk, const uint8_t in[6][16],
    uint8_t* out0, uint8_t* out1, uint8_t* out2, uint8_t* out3) {
  native_encrypt4_keys_6blocks_packed_impl(rk, in, out0, out1, out2, out3);

}

static int intel_sm4_ni_ok;
static ref_once_t intel_sm4_ni_once = REF_ONCE_INIT;
static void intel_sm4_ni_initialize(void) {
  if (!sm4th_x86_has_native_sm4()) return;
  static const uint8_t key[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                                  0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
  static const uint8_t expected[16] = {0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e,
                                       0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46};
  uint32_t rk[32];
  uint8_t ct[16];
  native_expand_key1_impl(key, rk);
  native_encrypt1_impl(rk, key, ct);
  intel_sm4_ni_ok = memcmp(ct, expected, sizeof(expected)) == 0;
}
#undef SM4_NI_TARGET
#endif

int intel_sm4_ni_supported(void) {
#if SM4TH_NATIVE_SM4_COMPILED
  /* CPUID and OS AVX state are checked before the first VSM4 instruction. */
  ref_call_once(&intel_sm4_ni_once, intel_sm4_ni_initialize);
  return intel_sm4_ni_ok;
#else
  return 0;
#endif
}

/* Design note:
 * - Keep the historical fast path lightweight: SM4NI4 + yuchen key schedule.
 * - Do not add round-key conversion or byte-swapping on the hot small-batch path.
 * - Only use wider kernels for clearly large batches (>= 16 blocks) where setup cost amortizes.
 * - Pad 1/2/3-block tails locally so AES-SM4NI also serves single-block OWFs. */

#if SM4TH_ENABLE_SM4_ACCE && (defined(__x86_64__) || defined(__i386__))
/* SM4NI declares its own GCC/Clang function target. */

#undef SM4_ROUNDS

#define sm4_key_schedule yuchen_sm4_key_schedule_impl
#define sm4_encrypt      yuchen_sm4_encrypt_impl
/* Avoid static helper name clash with utils.h */
#define load_u32_be      yuchen_sm4_ref_load_u32_be
#define store_u32_be     yuchen_sm4_ref_store_u32_be
#include "sm4ni/sm4_ref.c"
#undef store_u32_be
#undef load_u32_be

#include "sm4ni/sm4ni.c"

#undef sm4_encrypt
#undef sm4_key_schedule


static int sm4_set_key_yuchen(const uint8_t* key, SM4_KEY* ks) {
    uint32_t rk[SM4_KEY_SCHEDULE];
    yuchen_sm4_key_schedule_impl(key, rk);
    memcpy(ks->rk, rk, sizeof(rk));
    return 1;
}

//static void sm4_encrypt4_x86_sm4ni_yuchen(const SM4_KEY* ks, const uint8_t* src, uint8_t* dst) {
//    yuchen_sm4_encrypt4_impl(ks->rk, (void*)src, (const void*)dst);
//}

/* The optional assembly uses the Linux x86-64 ABI only. */
#if defined(__linux__) && defined(__x86_64__)
extern void sm4_aesni_avx2_asm_ecb_enc_blk_16(unsigned int* rk, unsigned char* dst,
                                          unsigned char* src) __attribute__((weak));
#else
static void (*const sm4_aesni_avx2_asm_ecb_enc_blk_16)(unsigned int*, unsigned char*,
                                                     unsigned char*) = NULL;
#endif

extern void sm4_encrypt4_opt(const uint32_t rk[32], const void* src, const void* dst);

static int sm4_has_avx2_ecb_kernel(void) {
    return sm4_aesni_avx2_asm_ecb_enc_blk_16 && sm4th_x86_has_aes_ssse3() &&
           sm4th_x86_has_avx2();
}
#endif

static unsigned int sm4_detect_acce_impl(void) {
    /* Native SM4 precedes AES simulation and scalar fallback. */
    if (intel_sm4_ni_supported()) return SM4_ACCE_IMPL_X86_NATIVE_SM4;
#if !SM4TH_ENABLE_SM4_ACCE
#if SM4TH_ENABLE_HYGON_CIS && defined(__x86_64__)
    if (hygon_cis_sm4_is_supported()) {
        return SM4_ACCE_IMPL_X86_HYGON_CIS;
    }
#endif
    return SM4_ACCE_IMPL_SCALAR;
#else
#if SM4TH_ENABLE_HYGON_CIS && defined(__x86_64__)
    if (hygon_cis_sm4_is_supported()) {
        return SM4_ACCE_IMPL_X86_HYGON_CIS;
    }
#endif
#if defined(__x86_64__) || defined(__i386__)
    if (sm4th_x86_has_aes_ssse3()) {
        return SM4_ACCE_IMPL_X86_SM4NI4;
    }
#endif
    return SM4_ACCE_IMPL_SCALAR;
#endif
}

int SM4_set_key_acce(const uint8_t* key, SM4_KEY* ks, unsigned int* impl) {
    unsigned int chosen_impl = SM4_ACCE_IMPL_SCALAR;

    if (!key || !ks) {
        return -1;
    }

    chosen_impl = sm4_detect_acce_impl();

#if SM4TH_NATIVE_SM4_COMPILED
    if (chosen_impl == SM4_ACCE_IMPL_X86_NATIVE_SM4) {
        intel_sm4_ni_expand_key1(key, ks->rk);
    } else
#endif

#if SM4TH_ENABLE_HYGON_CIS && defined(__x86_64__)
    if (chosen_impl == SM4_ACCE_IMPL_X86_HYGON_CIS) {
        hygon_cis_sm4_set_key(key, ks->rk);
    } else
#endif
#if SM4TH_ENABLE_SM4_ACCE && (defined(__x86_64__) || defined(__i386__))
    if (chosen_impl == SM4_ACCE_IMPL_X86_SM4NI4) {
        if (sm4_set_key_yuchen(key, ks) == 0) {
            return -1;
        }
    } else
#endif
    {
        if (SM4_set_key(key, ks) == 0) {
            return -1;
        }
    }

    if (impl) {
        *impl = chosen_impl;
    }

    return 0;
}

int SM4_encrypt_acce(const uint8_t* in, uint8_t* out, const SM4_KEY* ks, size_t blocks) {
    if (!in || !out || !ks) {
        return -1;
    }

#if SM4TH_NATIVE_SM4_COMPILED
    if (intel_sm4_ni_supported()) {
        /* Byte buffers may be unaligned; native kernels use unaligned loads. */
        while (blocks >= 2) {
            intel_sm4_ni_encrypt2_same_key(ks->rk,
                (const uint8_t (*)[16])(const void*)in, (uint8_t (*)[16])(void*)out);
            in += 32; out += 32; blocks -= 2;
        }
        if (blocks) intel_sm4_ni_encrypt1(ks->rk, in, out);
        return 0;
    }
#endif

#if SM4TH_ENABLE_HYGON_CIS && defined(__x86_64__)
    if (hygon_cis_sm4_is_supported()) {
        hygon_cis_sm4_encrypt_blocks(ks->rk, in, out, blocks);
        return 0;
    }
#endif

#if SM4TH_ENABLE_SM4_ACCE && (defined(__x86_64__) || defined(__i386__))
    const int has_sm4ni4 = sm4th_x86_has_aes_ssse3();
    const int has_avx2_kernel = sm4_has_avx2_ecb_kernel();

    if (has_sm4ni4 && (blocks == 4)) {
        sm4_encrypt4_opt(ks->rk, in, out);
        return 0;
    }

    if (has_avx2_kernel) {
        while (blocks >= 16) {
            sm4_aesni_avx2_asm_ecb_enc_blk_16((unsigned int*)ks->rk, out, (unsigned char*)in);
            blocks -= 16;
            in += 16 * PRG_BLOCK_SIZE;
            out += 16 * PRG_BLOCK_SIZE;
        }
    }

    if (has_sm4ni4) {
        for (; blocks >= 4; blocks -= 4, in += 4 * PRG_BLOCK_SIZE, out += 4 * PRG_BLOCK_SIZE) {
            sm4_encrypt4_opt(ks->rk, in, out);
        }
        if (blocks) {
            /* Do not read or write beyond a 1/2/3-block request. */
            uint8_t tail_in[64] = {0};
            uint8_t tail_out[64];
            memcpy(tail_in, in, blocks * PRG_BLOCK_SIZE);
            sm4_encrypt4_opt(ks->rk, tail_in, tail_out);
            memcpy(out, tail_out, blocks * PRG_BLOCK_SIZE);
            return 0;
        }
    }
#endif

    for (; blocks; --blocks, in += PRG_BLOCK_SIZE, out += PRG_BLOCK_SIZE) {
        SM4_encrypt(in, out, ks);
    }
    return 0;
}

/* ================================================================== *
 *  Generic SM4-ECB PRG wrapper (public)
 * ================================================================== */

int generic_sm4_ecb_new(generic_sm4_ecb_t* ctx, const uint8_t* key, unsigned int seclvl) {
    (void) seclvl; /* SM4 supports 128-bit keys only in this code */
    if (!ctx || !key) return -1;
    if (SM4_set_key_acce(key, &ctx->ks, &ctx->acce_impl) != 0) return -1;
    ctx->seclvl = seclvl;
    return 0;
}

int generic_sm4_ecb_encrypt(generic_sm4_ecb_t* ctx, uint8_t* ciphertext, const uint8_t* plaintext,
                            size_t blocks) {
    if (!ctx) return -1;
    return SM4_encrypt_acce(plaintext, ciphertext, &ctx->ks, blocks);
}

void generic_sm4_ecb_free(generic_sm4_ecb_t* ctx) {
    if (!ctx) return;
    explicit_bzero(&ctx->ks, sizeof(ctx->ks));
    ctx->acce_impl = SM4_ACCE_IMPL_SCALAR;
}
