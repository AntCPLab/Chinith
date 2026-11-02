#ifndef SM4TH_X86_CAPS_H
#define SM4TH_X86_CAPS_H

/* ISA kernels are optional; every entry is gated at runtime. */
#include "compat.h"
#if (defined(__x86_64__) || defined(__i386__)) && (defined(__GNUC__) || defined(__clang__))
#include <cpuid.h>
#define SM4TH_X86_TARGET 1
#else
#define SM4TH_X86_TARGET 0
#endif

enum {
  SM4TH_X86_CAP_AES        = 1u << 0,
  SM4TH_X86_CAP_SSSE3      = 1u << 1,
  SM4TH_X86_CAP_AVX2       = 1u << 2,
  SM4TH_X86_CAP_PCLMUL     = 1u << 3,
  SM4TH_X86_CAP_SSE41      = 1u << 4,
  SM4TH_X86_CAP_NATIVE_SM4 = 1u << 5,
  SM4TH_X86_CAP_AVX512F_VL = 1u << 6,
  SM4TH_X86_CAP_AVX512BW   = 1u << 7,
};

/* Publish CPU capabilities once without racing concurrent first calls. */
#if SM4TH_X86_TARGET
static unsigned int sm4th_x86_caps = 0;
static void sm4th_x86_init_caps(void) {
  unsigned int eax, ebx, ecx, edx;
  __builtin_cpu_init();
  if (__builtin_cpu_supports("aes")) sm4th_x86_caps |= SM4TH_X86_CAP_AES;
  if (__builtin_cpu_supports("ssse3")) sm4th_x86_caps |= SM4TH_X86_CAP_SSSE3;
  if (__builtin_cpu_supports("pclmul")) sm4th_x86_caps |= SM4TH_X86_CAP_PCLMUL;
  if (__builtin_cpu_supports("sse4.1")) sm4th_x86_caps |= SM4TH_X86_CAP_SSE41;
  /* Compiler AVX2 detection includes OSXSAVE/XCR0 usability. */
  if (__builtin_cpu_supports("avx2")) sm4th_x86_caps |= SM4TH_X86_CAP_AVX2;
  /* AVX-512 specialization requires compiler-detected OS support. */
  if (__builtin_cpu_supports("avx512f") && __builtin_cpu_supports("avx512vl"))
    sm4th_x86_caps |= SM4TH_X86_CAP_AVX512F_VL;
  if (__builtin_cpu_supports("avx512bw")) sm4th_x86_caps |= SM4TH_X86_CAP_AVX512BW;
#if defined(__x86_64__)
  __cpuid(0, eax, ebx, ecx, edx);
  const unsigned int max_basic = eax;
  if (max_basic >= 7u && (sm4th_x86_caps & SM4TH_X86_CAP_AVX2) != 0u) {
    __cpuid_count(7, 0, eax, ebx, ecx, edx);
    if (eax >= 1u) {
      __cpuid_count(7, 1, eax, ebx, ecx, edx);
      if ((eax & (1u << 2)) != 0u) sm4th_x86_caps |= SM4TH_X86_CAP_NATIVE_SM4;
    }
  }
#endif
}
#endif
static inline unsigned int sm4th_x86_get_caps(void) {
#if SM4TH_X86_TARGET
  static ref_once_t once = REF_ONCE_INIT;
  ref_call_once(&once, sm4th_x86_init_caps);
  /* Tests may only mask detected features, never enable an ISA. */
#ifdef SM4TH_TEST_CPU_CAP_MASK
  return sm4th_x86_caps & (unsigned int)SM4TH_TEST_CPU_CAP_MASK;
#else
  return sm4th_x86_caps;
#endif
#else
  return 0;
#endif
}

static inline int sm4th_x86_has_aes_ssse3(void) {
  const unsigned int caps = sm4th_x86_get_caps();
  const unsigned int want = SM4TH_X86_CAP_AES | SM4TH_X86_CAP_SSSE3;
  return (caps & want) == want;
}
static inline int sm4th_x86_has_avx2(void) {
  return (sm4th_x86_get_caps() & SM4TH_X86_CAP_AVX2) != 0;
}
/* Masked dependencies must all remain present before ISA entry. */
static inline int sm4th_x86_has_avx512f_vl(void) {
  const unsigned int want = SM4TH_X86_CAP_AVX2 | SM4TH_X86_CAP_AVX512F_VL;
  return (sm4th_x86_get_caps() & want) == want;
}
static inline int sm4th_x86_has_avx512bw_vl(void) {
  const unsigned int want = SM4TH_X86_CAP_AVX2 | SM4TH_X86_CAP_AVX512F_VL |
                            SM4TH_X86_CAP_AVX512BW;
  return (sm4th_x86_get_caps() & want) == want;
}
static inline int sm4th_x86_has_pclmul(void) {
  const unsigned int want = SM4TH_X86_CAP_PCLMUL | SM4TH_X86_CAP_SSSE3 | SM4TH_X86_CAP_SSE41;
  return (sm4th_x86_get_caps() & want) == want;
}
static inline int sm4th_x86_has_native_sm4(void) {
  return (sm4th_x86_get_caps() & (SM4TH_X86_CAP_NATIVE_SM4 | SM4TH_X86_CAP_AVX2)) ==
         (SM4TH_X86_CAP_NATIVE_SM4 | SM4TH_X86_CAP_AVX2);
}
#endif
