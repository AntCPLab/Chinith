/* Unused signature-independent helpers were removed; active backend entrypoints remain. */
/*
 * SPDX-License-Identifier: MIT
 */

#include <assert.h>

#include "owf.h"
#include "utils_sm4/sm4.h"

void owf_sm4_128(const uint8_t* key, const uint8_t* input, uint8_t* output) {
  generic_sm4_ecb_t ctx;
  int ret = generic_sm4_ecb_new(&ctx, key, 128);
  assert(ret == 0);
  (void)ret;

  ret = generic_sm4_ecb_encrypt(&ctx, output, input, 1);
  assert(ret == 0);
  (void)ret;

  generic_sm4_ecb_free(&ctx);
}

