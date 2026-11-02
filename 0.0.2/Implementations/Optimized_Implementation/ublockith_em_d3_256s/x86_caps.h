#ifndef UBLOCKITH_X86_CAPS_H
#define UBLOCKITH_X86_CAPS_H

#include "compat.h"

/*
 * Shared x86 feature probing helpers.
 * Cache only AVX2, the feature used by the uBlock/Ballet paths.
 */

enum {
  UBLOCKITH_X86_CAP_AVX2  = 1u << 2,
};

/* Publish the Optimized-only feature cache once before concurrent use. */
#if defined(__x86_64__) || defined(__i386__)
static unsigned int ublockith_x86_caps = 0;
static void ublockith_x86_caps_initialize(void) {
#if defined(__GNUC__) || defined(__clang__)
  __builtin_cpu_init();
  if (__builtin_cpu_supports("avx2")) {
    ublockith_x86_caps |= UBLOCKITH_X86_CAP_AVX2;
  }
#endif
}
#endif

static inline unsigned int ublockith_x86_get_caps(void) {
#if defined(__x86_64__) || defined(__i386__)
  static ref_once_t once = REF_ONCE_INIT;
  ref_call_once(&once, ublockith_x86_caps_initialize);
  return ublockith_x86_caps;
#else
  return 0;
#endif
}

static inline int ublockith_x86_has_avx2(void) {
  return (ublockith_x86_get_caps() & UBLOCKITH_X86_CAP_AVX2) != 0;
}

#endif
