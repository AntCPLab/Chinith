#include "universal_hashing.h"

#include "params.h"
#include "utils.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

static inline unsigned int vh_lambda_bytes(void) { return BF512_NUM_BYTES; }
static inline unsigned int vh_lambda_bits(void) { return BF512_NUM_BYTES * 8u; }

/* Hash only x0_bits prefix bits, then XOR the final lambda+B bits. */
static inline bf64_t vh_h1_word(const uint8_t* x, unsigned int x0_bits,
                                size_t total_words, size_t word) {
  const size_t offset = (total_words - 1u - word) * 8u;
  const size_t prefix_bytes = x0_bits / 8u;
  if (offset + 8u <= prefix_bytes) {
    return bf64_load(x + offset);
  }
  uint8_t tmp[8] = {0};
  if (offset < prefix_bytes) {
    memcpy(tmp, x + offset, prefix_bytes - offset);
  }
  return bf64_load(tmp);
}

static bf64_t compute_h1(const uint8_t* t, const uint8_t* x, unsigned int x0_bits) {
  /* Evaluate h1 over contiguous padded x0 words in every lane. */
  const unsigned int lambda = vh_lambda_bits();
  const size_t padded_bytes = ((x0_bits + lambda - 1u) / lambda) * (lambda / 8u);
  const size_t total_words = (padded_bytes + 7u) / 8u;
  const bf64_t b_t = bf64_load(t);
  bf64_t running_t = bf64_one();
  const uint8_t* lanes[1] = {x};
  bf64_t accum[1] = {bf64_zero()};
  for (size_t word = 0; word < total_words; ++word, running_t = bf64_mul(running_t, b_t)) {
    const bf64_t coeff = running_t;
    for (size_t lane = 0; lane < 1u; ++lane) {
      const bf64_t v = vh_h1_word(lanes[lane], x0_bits, total_words, word);
      accum[lane] = bf64_add(accum[lane], bf64_mul(coeff, v));
    }
  }
  return accum[0];
}

static inline void compute_h1_2(const uint8_t* t, const uint8_t* x0, const uint8_t* x1,
                                unsigned int x0_bits, bf64_t* h1_0, bf64_t* h1_1) {
  /* Evaluate h1 over contiguous padded x0 words in every lane. */
  const unsigned int lambda = vh_lambda_bits();
  const size_t padded_bytes = ((x0_bits + lambda - 1u) / lambda) * (lambda / 8u);
  const size_t total_words = (padded_bytes + 7u) / 8u;
  const bf64_t b_t = bf64_load(t);
  bf64_t running_t = bf64_one();
  const uint8_t* lanes[2] = {x0, x1};
  bf64_t accum[2] = {bf64_zero(), bf64_zero()};
  for (size_t word = 0; word < total_words; ++word, running_t = bf64_mul(running_t, b_t)) {
    const bf64_t coeff = running_t;
    for (size_t lane = 0; lane < 2u; ++lane) {
      const bf64_t v = vh_h1_word(lanes[lane], x0_bits, total_words, word);
      accum[lane] = bf64_add(accum[lane], bf64_mul(coeff, v));
    }
  }
  *h1_0 = accum[0];
  *h1_1 = accum[1];
}

static inline void compute_h1_4(const uint8_t* t, const uint8_t* x0, const uint8_t* x1,
                                const uint8_t* x2, const uint8_t* x3, unsigned int x0_bits,
                                bf64_t* h1_0, bf64_t* h1_1, bf64_t* h1_2, bf64_t* h1_3) {
  /* Evaluate h1 over contiguous padded x0 words in every lane. */
  const unsigned int lambda = vh_lambda_bits();
  const size_t padded_bytes = ((x0_bits + lambda - 1u) / lambda) * (lambda / 8u);
  const size_t total_words = (padded_bytes + 7u) / 8u;
  const bf64_t b_t = bf64_load(t);
  bf64_t running_t = bf64_one();
  const uint8_t* lanes[4] = {x0, x1, x2, x3};
  bf64_t accum[4] = {bf64_zero(), bf64_zero(), bf64_zero(), bf64_zero()};
  for (size_t word = 0; word < total_words; ++word, running_t = bf64_mul(running_t, b_t)) {
    const bf64_t coeff = running_t;
    for (size_t lane = 0; lane < 4u; ++lane) {
      const bf64_t v = vh_h1_word(lanes[lane], x0_bits, total_words, word);
      accum[lane] = bf64_add(accum[lane], bf64_mul(coeff, v));
    }
  }
  *h1_0 = accum[0];
  *h1_1 = accum[1];
  *h1_2 = accum[2];
  *h1_3 = accum[3];
}

int vole_hash_precompute_init(vole_hash_precomp_t* ctx, const uint8_t* sd, unsigned int x0_bits,
                              uint32_t lambda) {
  if (!ctx || !sd || lambda != 512u) {
    return 0;
  }

  memset(ctx, 0, sizeof(*ctx));
  ctx->sd = sd;
  /* Precompute using the same prefix split as scalar and batch hashes. */
  ctx->x0_bits = x0_bits;
  ctx->length_lambda = (x0_bits + vh_lambda_bits() - 1u) / vh_lambda_bits();
  ctx->last_bytes = (x0_bits % vh_lambda_bits() == 0u)
                        ? vh_lambda_bytes()
                        : (x0_bits % vh_lambda_bits()) / 8u;
  ctx->total_words = ((size_t)ctx->length_lambda * vh_lambda_bytes() + 7u) / 8u;

  ctx->t_pows = malloc(ctx->total_words * sizeof(*ctx->t_pows));
  if (!ctx->t_pows) {
    return 0;
  }

  {
    const uint8_t* t = sd + 5u * vh_lambda_bytes();
    const bf64_t b_t = bf64_load(t);
    bf64_t running_t = bf64_one();
    for (size_t i = 0; i < ctx->total_words; ++i, running_t = bf64_mul(running_t, b_t)) {
      ctx->t_pows[i] = running_t;
    }
  }

  if (ctx->length_lambda > 1u) {
    const size_t pcount = (size_t)ctx->length_lambda - 1u;
    const uint8_t* s = sd + 4u * vh_lambda_bytes();
    ctx->s_pows_512 = malloc(pcount * sizeof(*ctx->s_pows_512));
    if (!ctx->s_pows_512) {
      vole_hash_precompute_clear(ctx);
      return 0;
    }
    bf512_t running_s = bf512_load(s);
    const bf512_t b_s = running_s;
    for (size_t i = 0; i < pcount; ++i, running_s = bf512_mul(running_s, b_s)) {
      ctx->s_pows_512[i] = running_s;
    }
  }

  return 1;
}

void vole_hash_precompute_clear(vole_hash_precomp_t* ctx) {
  if (!ctx) {
    return;
  }
  free(ctx->t_pows);
  free(ctx->s_pows_512);
  memset(ctx, 0, sizeof(*ctx));
}

static inline void compute_h1_4_precomp(const vole_hash_precomp_t* ctx, const uint8_t* x0,
                                        const uint8_t* x1, const uint8_t* x2, const uint8_t* x3,
                                        bf64_t* h1_0, bf64_t* h1_1, bf64_t* h1_2, bf64_t* h1_3) {
  /* Evaluate h1 over contiguous padded x0 words in every lane. */
  const size_t total_words = ctx->total_words;
  const uint8_t* lanes[4] = {x0, x1, x2, x3};
  bf64_t accum[4] = {bf64_zero(), bf64_zero(), bf64_zero(), bf64_zero()};
  for (size_t word = 0; word < total_words; ++word) {
    const bf64_t coeff = ctx->t_pows[word];
    for (size_t lane = 0; lane < 4u; ++lane) {
      const bf64_t v = vh_h1_word(lanes[lane], ctx->x0_bits, total_words, word);
      accum[lane] = bf64_add(accum[lane], bf64_mul(coeff, v));
    }
  }
  *h1_0 = accum[0];
  *h1_1 = accum[1];
  *h1_2 = accum[2];
  *h1_3 = accum[3];
}

static void vole_hash_512_4_precomp(uint8_t* h0_out, uint8_t* h1_out, uint8_t* h2_out,
                                    uint8_t* h3_out, const vole_hash_precomp_t* ctx,
                                    const uint8_t* x0, const uint8_t* x1, const uint8_t* x2,
                                    const uint8_t* x3) {
  const uint8_t* r0 = ctx->sd;
  const uint8_t* r1 = ctx->sd + 1 * BF512_NUM_BYTES;
  const uint8_t* r2 = ctx->sd + 2 * BF512_NUM_BYTES;
  const uint8_t* r3 = ctx->sd + 3 * BF512_NUM_BYTES;
  /* Keep the padded prefix and final mask slice disjoint. */
  const uint8_t* x0_tail = x0 + ctx->x0_bits / 8;
  /* Keep the padded prefix and final mask slice disjoint. */
  const uint8_t* x1_tail = x1 + ctx->x0_bits / 8;
  /* Keep the padded prefix and final mask slice disjoint. */
  const uint8_t* x2_tail = x2 + ctx->x0_bits / 8;
  /* Keep the padded prefix and final mask slice disjoint. */
  const uint8_t* x3_tail = x3 + ctx->x0_bits / 8;

  uint8_t tmp0[BF512_NUM_BYTES] = {0};
  uint8_t tmp1[BF512_NUM_BYTES] = {0};
  uint8_t tmp2[BF512_NUM_BYTES] = {0};
  uint8_t tmp3[BF512_NUM_BYTES] = {0};
  memcpy(tmp0, x0 + (size_t)(ctx->length_lambda - 1u) * BF512_NUM_BYTES, ctx->last_bytes);
  memcpy(tmp1, x1 + (size_t)(ctx->length_lambda - 1u) * BF512_NUM_BYTES, ctx->last_bytes);
  memcpy(tmp2, x2 + (size_t)(ctx->length_lambda - 1u) * BF512_NUM_BYTES, ctx->last_bytes);
  memcpy(tmp3, x3 + (size_t)(ctx->length_lambda - 1u) * BF512_NUM_BYTES, ctx->last_bytes);
  bf512_t h0_0 = bf512_load(tmp0);
  bf512_t h0_1 = bf512_load(tmp1);
  bf512_t h0_2 = bf512_load(tmp2);
  bf512_t h0_3 = bf512_load(tmp3);

  for (unsigned int i = 1; i != ctx->length_lambda; ++i) {
    const size_t off = (size_t)(ctx->length_lambda - 1u - i) * BF512_NUM_BYTES;
    const bf512_t coeff = ctx->s_pows_512[i - 1u];
    h0_0 = bf512_add(h0_0, bf512_mul(coeff, bf512_load(x0 + off)));
    h0_1 = bf512_add(h0_1, bf512_mul(coeff, bf512_load(x1 + off)));
    h0_2 = bf512_add(h0_2, bf512_mul(coeff, bf512_load(x2 + off)));
    h0_3 = bf512_add(h0_3, bf512_mul(coeff, bf512_load(x3 + off)));
  }

  bf64_t h1_0;
  bf64_t h1_1;
  bf64_t h1_2;
  bf64_t h1_3;
  compute_h1_4_precomp(ctx, x0, x1, x2, x3, &h1_0, &h1_1, &h1_2, &h1_3);
  const bf512_t br0 = bf512_load(r0);
  const bf512_t br1 = bf512_load(r1);
  const bf512_t br2 = bf512_load(r2);
  const bf512_t br3 = bf512_load(r3);

  bf512_t hh2_0 = bf512_add(bf512_mul(br0, h0_0), bf512_mul_64(br1, h1_0));
  bf512_t hh3_0 = bf512_add(bf512_mul(br2, h0_0), bf512_mul_64(br3, h1_0));
  bf512_t hh2_1 = bf512_add(bf512_mul(br0, h0_1), bf512_mul_64(br1, h1_1));
  bf512_t hh3_1 = bf512_add(bf512_mul(br2, h0_1), bf512_mul_64(br3, h1_1));
  bf512_t hh2_2 = bf512_add(bf512_mul(br0, h0_2), bf512_mul_64(br1, h1_2));
  bf512_t hh3_2 = bf512_add(bf512_mul(br2, h0_2), bf512_mul_64(br3, h1_2));
  bf512_t hh2_3 = bf512_add(bf512_mul(br0, h0_3), bf512_mul_64(br1, h1_3));
  bf512_t hh3_3 = bf512_add(bf512_mul(br2, h0_3), bf512_mul_64(br3, h1_3));

  bf512_store(h0_out, hh2_0);
  bf512_store(tmp0, hh3_0);
  memcpy(h0_out + BF512_NUM_BYTES, tmp0, UNIVERSAL_HASH_B);
  xor_u8_array(h0_out, x0_tail, h0_out, BF512_NUM_BYTES + UNIVERSAL_HASH_B);

  bf512_store(h1_out, hh2_1);
  bf512_store(tmp1, hh3_1);
  memcpy(h1_out + BF512_NUM_BYTES, tmp1, UNIVERSAL_HASH_B);
  xor_u8_array(h1_out, x1_tail, h1_out, BF512_NUM_BYTES + UNIVERSAL_HASH_B);

  bf512_store(h2_out, hh2_2);
  bf512_store(tmp2, hh3_2);
  memcpy(h2_out + BF512_NUM_BYTES, tmp2, UNIVERSAL_HASH_B);
  xor_u8_array(h2_out, x2_tail, h2_out, BF512_NUM_BYTES + UNIVERSAL_HASH_B);

  bf512_store(h3_out, hh2_3);
  bf512_store(tmp3, hh3_3);
  memcpy(h3_out + BF512_NUM_BYTES, tmp3, UNIVERSAL_HASH_B);
  xor_u8_array(h3_out, x3_tail, h3_out, BF512_NUM_BYTES + UNIVERSAL_HASH_B);
}

void vole_hash_4_precomp(uint8_t* h0, uint8_t* h1, uint8_t* h2, uint8_t* h3,
                         const vole_hash_precomp_t* ctx, const uint8_t* x0, const uint8_t* x1,
                         const uint8_t* x2, const uint8_t* x3) {
  vole_hash_512_4_precomp(h0, h1, h2, h3, ctx, x0, x1, x2, x3);
}

void vole_hash_2_precomp(uint8_t* h0, uint8_t* h1, const vole_hash_precomp_t* ctx,
                         const uint8_t* x0, const uint8_t* x1) {
  uint8_t throw2[BF512_NUM_BYTES + UNIVERSAL_HASH_B];
  uint8_t throw3[BF512_NUM_BYTES + UNIVERSAL_HASH_B];
  vole_hash_4_precomp(h0, h1, throw2, throw3, ctx, x0, x1, x0, x1);
}

void vole_hash_precomp(uint8_t* h0, const vole_hash_precomp_t* ctx, const uint8_t* x0) {
  uint8_t throw1[BF512_NUM_BYTES + UNIVERSAL_HASH_B];
  uint8_t throw2[BF512_NUM_BYTES + UNIVERSAL_HASH_B];
  uint8_t throw3[BF512_NUM_BYTES + UNIVERSAL_HASH_B];
  vole_hash_4_precomp(h0, throw1, throw2, throw3, ctx, x0, x0, x0, x0);
}

void vole_hash_512(uint8_t* h, const uint8_t* sd, const uint8_t* x, unsigned int x0_bits) {
  const uint8_t* r0 = sd;
  const uint8_t* r1 = sd + 1 * BF512_NUM_BYTES;
  const uint8_t* r2 = sd + 2 * BF512_NUM_BYTES;
  const uint8_t* r3 = sd + 3 * BF512_NUM_BYTES;
  const uint8_t* s  = sd + 4 * BF512_NUM_BYTES;
  const uint8_t* t  = sd + 5 * BF512_NUM_BYTES;
  /* Keep the padded prefix and final mask slice disjoint. */
  const uint8_t* x1 = x + x0_bits / 8;

  /* Keep the padded prefix and final mask slice disjoint. */
  const unsigned int length_lambda = (x0_bits + BF512_NUM_BYTES * 8 - 1) / (BF512_NUM_BYTES * 8);

  uint8_t tmp[BF512_NUM_BYTES] = {0};
  memcpy(tmp, x + (length_lambda - 1) * BF512_NUM_BYTES,
         x0_bits % (BF512_NUM_BYTES * 8) == 0
             ? BF512_NUM_BYTES
             : (x0_bits % (BF512_NUM_BYTES * 8)) / 8);
  bf512_t h0 = bf512_load(tmp);

  const bf512_t b_s = bf512_load(s);
  bf512_t running_s = b_s;
  for (unsigned int i = 1; i != length_lambda; ++i, running_s = bf512_mul(running_s, b_s)) {
    h0 = bf512_add(h0,
                   bf512_mul(running_s, bf512_load(x + (length_lambda - 1 - i) * BF512_NUM_BYTES)));
  }

  const bf64_t h1 = compute_h1(t, x, x0_bits);
  const bf512_t h2 = bf512_add(bf512_mul(bf512_load(r0), h0), bf512_mul_64(bf512_load(r1), h1));
  const bf512_t h3 = bf512_add(bf512_mul(bf512_load(r2), h0), bf512_mul_64(bf512_load(r3), h1));

  bf512_store(h, h2);
  bf512_store(tmp, h3);
  memcpy(h + BF512_NUM_BYTES, tmp, UNIVERSAL_HASH_B);
  xor_u8_array(h, x1, h, BF512_NUM_BYTES + UNIVERSAL_HASH_B);
}

void vole_hash_512_2(uint8_t* h0_out, uint8_t* h1_out, const uint8_t* sd, const uint8_t* x0,
                     const uint8_t* x1, unsigned int x0_bits) {
  const uint8_t* r0 = sd;
  const uint8_t* r1 = sd + 1 * BF512_NUM_BYTES;
  const uint8_t* r2 = sd + 2 * BF512_NUM_BYTES;
  const uint8_t* r3 = sd + 3 * BF512_NUM_BYTES;
  const uint8_t* s  = sd + 4 * BF512_NUM_BYTES;
  const uint8_t* t  = sd + 5 * BF512_NUM_BYTES;
  /* Keep the padded prefix and final mask slice disjoint. */
  const uint8_t* x0_tail = x0 + x0_bits / 8;
  /* Keep the padded prefix and final mask slice disjoint. */
  const uint8_t* x1_tail = x1 + x0_bits / 8;

  /* Keep the padded prefix and final mask slice disjoint. */
  const unsigned int length_lambda = (x0_bits + BF512_NUM_BYTES * 8 - 1) / (BF512_NUM_BYTES * 8);
  const size_t last_bytes = x0_bits % (BF512_NUM_BYTES * 8) == 0
                                ? BF512_NUM_BYTES
                                : (x0_bits % (BF512_NUM_BYTES * 8)) / 8;

  uint8_t tmp0[BF512_NUM_BYTES] = {0};
  uint8_t tmp1[BF512_NUM_BYTES] = {0};
  memcpy(tmp0, x0 + (length_lambda - 1) * BF512_NUM_BYTES, last_bytes);
  memcpy(tmp1, x1 + (length_lambda - 1) * BF512_NUM_BYTES, last_bytes);
  bf512_t h0_0 = bf512_load(tmp0);
  bf512_t h0_1 = bf512_load(tmp1);

  const bf512_t b_s = bf512_load(s);
  bf512_t running_s = b_s;
  for (unsigned int i = 1; i != length_lambda; ++i, running_s = bf512_mul(running_s, b_s)) {
    const size_t off = (length_lambda - 1 - i) * BF512_NUM_BYTES;
    h0_0 = bf512_add(h0_0, bf512_mul(running_s, bf512_load(x0 + off)));
    h0_1 = bf512_add(h0_1, bf512_mul(running_s, bf512_load(x1 + off)));
  }

  bf64_t h1_0;
  bf64_t h1_1;
  compute_h1_2(t, x0, x1, x0_bits, &h1_0, &h1_1);
  const bf512_t br0 = bf512_load(r0);
  const bf512_t br1 = bf512_load(r1);
  const bf512_t br2 = bf512_load(r2);
  const bf512_t br3 = bf512_load(r3);

  bf512_t h2_0 = bf512_add(bf512_mul(br0, h0_0), bf512_mul_64(br1, h1_0));
  bf512_t h3_0 = bf512_add(bf512_mul(br2, h0_0), bf512_mul_64(br3, h1_0));
  bf512_t h2_1 = bf512_add(bf512_mul(br0, h0_1), bf512_mul_64(br1, h1_1));
  bf512_t h3_1 = bf512_add(bf512_mul(br2, h0_1), bf512_mul_64(br3, h1_1));

  bf512_store(h0_out, h2_0);
  bf512_store(tmp0, h3_0);
  memcpy(h0_out + BF512_NUM_BYTES, tmp0, UNIVERSAL_HASH_B);
  xor_u8_array(h0_out, x0_tail, h0_out, BF512_NUM_BYTES + UNIVERSAL_HASH_B);

  bf512_store(h1_out, h2_1);
  bf512_store(tmp1, h3_1);
  memcpy(h1_out + BF512_NUM_BYTES, tmp1, UNIVERSAL_HASH_B);
  xor_u8_array(h1_out, x1_tail, h1_out, BF512_NUM_BYTES + UNIVERSAL_HASH_B);
}

void vole_hash_512_4(uint8_t* h0_out, uint8_t* h1_out, uint8_t* h2_out, uint8_t* h3_out,
                     const uint8_t* sd, const uint8_t* x0, const uint8_t* x1,
                     const uint8_t* x2, const uint8_t* x3, unsigned int x0_bits) {
  const uint8_t* r0 = sd;
  const uint8_t* r1 = sd + 1 * BF512_NUM_BYTES;
  const uint8_t* r2 = sd + 2 * BF512_NUM_BYTES;
  const uint8_t* r3 = sd + 3 * BF512_NUM_BYTES;
  const uint8_t* s  = sd + 4 * BF512_NUM_BYTES;
  const uint8_t* t  = sd + 5 * BF512_NUM_BYTES;
  /* Keep the padded prefix and final mask slice disjoint. */
  const uint8_t* x0_tail = x0 + x0_bits / 8;
  /* Keep the padded prefix and final mask slice disjoint. */
  const uint8_t* x1_tail = x1 + x0_bits / 8;
  /* Keep the padded prefix and final mask slice disjoint. */
  const uint8_t* x2_tail = x2 + x0_bits / 8;
  /* Keep the padded prefix and final mask slice disjoint. */
  const uint8_t* x3_tail = x3 + x0_bits / 8;

  /* Keep the padded prefix and final mask slice disjoint. */
  const unsigned int length_lambda = (x0_bits + BF512_NUM_BYTES * 8 - 1) / (BF512_NUM_BYTES * 8);
  const size_t last_bytes = x0_bits % (BF512_NUM_BYTES * 8) == 0
                                ? BF512_NUM_BYTES
                                : (x0_bits % (BF512_NUM_BYTES * 8)) / 8;

  uint8_t tmp0[BF512_NUM_BYTES] = {0};
  uint8_t tmp1[BF512_NUM_BYTES] = {0};
  uint8_t tmp2[BF512_NUM_BYTES] = {0};
  uint8_t tmp3[BF512_NUM_BYTES] = {0};
  memcpy(tmp0, x0 + (length_lambda - 1) * BF512_NUM_BYTES, last_bytes);
  memcpy(tmp1, x1 + (length_lambda - 1) * BF512_NUM_BYTES, last_bytes);
  memcpy(tmp2, x2 + (length_lambda - 1) * BF512_NUM_BYTES, last_bytes);
  memcpy(tmp3, x3 + (length_lambda - 1) * BF512_NUM_BYTES, last_bytes);
  bf512_t h0_0 = bf512_load(tmp0);
  bf512_t h0_1 = bf512_load(tmp1);
  bf512_t h0_2 = bf512_load(tmp2);
  bf512_t h0_3 = bf512_load(tmp3);

  const bf512_t b_s = bf512_load(s);
  bf512_t running_s = b_s;
  for (unsigned int i = 1; i != length_lambda; ++i, running_s = bf512_mul(running_s, b_s)) {
    const size_t off = (length_lambda - 1 - i) * BF512_NUM_BYTES;
    h0_0 = bf512_add(h0_0, bf512_mul(running_s, bf512_load(x0 + off)));
    h0_1 = bf512_add(h0_1, bf512_mul(running_s, bf512_load(x1 + off)));
    h0_2 = bf512_add(h0_2, bf512_mul(running_s, bf512_load(x2 + off)));
    h0_3 = bf512_add(h0_3, bf512_mul(running_s, bf512_load(x3 + off)));
  }

  bf64_t h1_0;
  bf64_t h1_1;
  bf64_t h1_2;
  bf64_t h1_3;
  compute_h1_4(t, x0, x1, x2, x3, x0_bits, &h1_0, &h1_1, &h1_2, &h1_3);
  const bf512_t br0 = bf512_load(r0);
  const bf512_t br1 = bf512_load(r1);
  const bf512_t br2 = bf512_load(r2);
  const bf512_t br3 = bf512_load(r3);

  bf512_t hh2_0 = bf512_add(bf512_mul(br0, h0_0), bf512_mul_64(br1, h1_0));
  bf512_t hh3_0 = bf512_add(bf512_mul(br2, h0_0), bf512_mul_64(br3, h1_0));
  bf512_t hh2_1 = bf512_add(bf512_mul(br0, h0_1), bf512_mul_64(br1, h1_1));
  bf512_t hh3_1 = bf512_add(bf512_mul(br2, h0_1), bf512_mul_64(br3, h1_1));
  bf512_t hh2_2 = bf512_add(bf512_mul(br0, h0_2), bf512_mul_64(br1, h1_2));
  bf512_t hh3_2 = bf512_add(bf512_mul(br2, h0_2), bf512_mul_64(br3, h1_2));
  bf512_t hh2_3 = bf512_add(bf512_mul(br0, h0_3), bf512_mul_64(br1, h1_3));
  bf512_t hh3_3 = bf512_add(bf512_mul(br2, h0_3), bf512_mul_64(br3, h1_3));

  bf512_store(h0_out, hh2_0);
  bf512_store(tmp0, hh3_0);
  memcpy(h0_out + BF512_NUM_BYTES, tmp0, UNIVERSAL_HASH_B);
  xor_u8_array(h0_out, x0_tail, h0_out, BF512_NUM_BYTES + UNIVERSAL_HASH_B);

  bf512_store(h1_out, hh2_1);
  bf512_store(tmp1, hh3_1);
  memcpy(h1_out + BF512_NUM_BYTES, tmp1, UNIVERSAL_HASH_B);
  xor_u8_array(h1_out, x1_tail, h1_out, BF512_NUM_BYTES + UNIVERSAL_HASH_B);

  bf512_store(h2_out, hh2_2);
  bf512_store(tmp2, hh3_2);
  memcpy(h2_out + BF512_NUM_BYTES, tmp2, UNIVERSAL_HASH_B);
  xor_u8_array(h2_out, x2_tail, h2_out, BF512_NUM_BYTES + UNIVERSAL_HASH_B);

  bf512_store(h3_out, hh2_3);
  bf512_store(tmp3, hh3_3);
  memcpy(h3_out + BF512_NUM_BYTES, tmp3, UNIVERSAL_HASH_B);
  xor_u8_array(h3_out, x3_tail, h3_out, BF512_NUM_BYTES + UNIVERSAL_HASH_B);
}

void vole_hash(uint8_t* h, const uint8_t* sd, const uint8_t* x, unsigned int x0_bits, uint32_t lambda) {
  (void)lambda;
  vole_hash_512(h, sd, x, x0_bits);
}

void vole_hash_2(uint8_t* h0, uint8_t* h1, const uint8_t* sd, const uint8_t* x0, const uint8_t* x1,
                 unsigned int x0_bits, uint32_t lambda) {
  (void)lambda;
  vole_hash_512_2(h0, h1, sd, x0, x1, x0_bits);
}

void vole_hash_4(uint8_t* h0, uint8_t* h1, uint8_t* h2, uint8_t* h3, const uint8_t* sd,
                 const uint8_t* x0, const uint8_t* x1, const uint8_t* x2, const uint8_t* x3,
                 unsigned int x0_bits, uint32_t lambda) {
  (void)lambda;
  vole_hash_512_4(h0, h1, h2, h3, sd, x0, x1, x2, x3, x0_bits);
}

void zk_hash_512_init(zk_hash_512_ctx* ctx, const uint8_t* sd) {
  const uint8_t* s = sd + 2 * BF512_NUM_BYTES;
  const uint8_t* t = sd + 3 * BF512_NUM_BYTES;

  ctx->h0      = bf512_zero();
  ctx->h1      = bf512_zero();
  ctx->s       = bf512_load(s);
  ctx->s2      = bf512_mul(ctx->s, ctx->s);
  ctx->t       = bf64_load(t);
  ctx->sd      = sd;
  ctx->pending = 0;
}

void zk_hash_512_update(zk_hash_512_ctx* ctx, bf512_t v) {
  if (!ctx->pending) {
    ctx->pending_v = v;
    ctx->pending   = 1;
  } else {
    ctx->h0 = bf512_add(bf512_add(bf512_mul(ctx->h0, ctx->s2), bf512_mul(ctx->pending_v, ctx->s)),
                        v);
    ctx->h1 = bf512_add(
        bf512_mul_64(bf512_add(bf512_mul_64(ctx->h1, ctx->t), ctx->pending_v), ctx->t), v);
    ctx->pending = 0;
  }
}

void zk_hash_512_finalize(uint8_t* h, zk_hash_512_ctx* ctx, bf512_t x1) {
  if (ctx->pending) {
    ctx->h0 = bf512_add(bf512_mul(ctx->h0, ctx->s), ctx->pending_v);
    ctx->h1 = bf512_add(bf512_mul_64(ctx->h1, ctx->t), ctx->pending_v);
    ctx->pending = 0;
  }
  const uint8_t* r0 = ctx->sd;
  const uint8_t* r1 = ctx->sd + BF512_NUM_BYTES;
  bf512_store(
      h, bf512_add(bf512_add(bf512_mul(bf512_load(r0), ctx->h0), bf512_mul(bf512_load(r1), ctx->h1)),
                   x1));
}

/* Vistrutith uses one- and three-coefficient hashes, never two. */

void zk_hash_512_3_init(zk_hash_512_3_ctx* ctx, const uint8_t* sd) {
  const uint8_t* s = sd + 2 * BF512_NUM_BYTES;
  const uint8_t* t = sd + 3 * BF512_NUM_BYTES;

  ctx->h0[0] = bf512_zero();
  ctx->h0[1] = bf512_zero();
  ctx->h0[2] = bf512_zero();
  ctx->h1[0] = bf512_zero();
  ctx->h1[1] = bf512_zero();
  ctx->h1[2] = bf512_zero();
  ctx->s       = bf512_load(s);
  ctx->s2      = bf512_mul(ctx->s, ctx->s);
  ctx->t       = bf64_load(t);
  ctx->sd      = sd;
  ctx->pending = 0;
}

void zk_hash_512_3_update(zk_hash_512_3_ctx* ctx, bf512_t v_0, bf512_t v_1, bf512_t v_2) {
  if (!ctx->pending) {
    ctx->pending_v_0 = v_0;
    ctx->pending_v_1 = v_1;
    ctx->pending_v_2 = v_2;
    ctx->pending     = 1;
  } else {
    ctx->h0[0] = bf512_add(
        bf512_add(bf512_mul(ctx->h0[0], ctx->s2), bf512_mul(ctx->pending_v_0, ctx->s)), v_0);
    ctx->h1[0] = bf512_add(
        bf512_mul_64(bf512_add(bf512_mul_64(ctx->h1[0], ctx->t), ctx->pending_v_0), ctx->t), v_0);
    ctx->h0[1] = bf512_add(
        bf512_add(bf512_mul(ctx->h0[1], ctx->s2), bf512_mul(ctx->pending_v_1, ctx->s)), v_1);
    ctx->h1[1] = bf512_add(
        bf512_mul_64(bf512_add(bf512_mul_64(ctx->h1[1], ctx->t), ctx->pending_v_1), ctx->t), v_1);
    ctx->h0[2] = bf512_add(
        bf512_add(bf512_mul(ctx->h0[2], ctx->s2), bf512_mul(ctx->pending_v_2, ctx->s)), v_2);
    ctx->h1[2] = bf512_add(
        bf512_mul_64(bf512_add(bf512_mul_64(ctx->h1[2], ctx->t), ctx->pending_v_2), ctx->t), v_2);
    ctx->pending = 0;
  }
}

/* Removed unused internal zk_hash_512_3_raise_and_update helper. */

void zk_hash_512_3_finalize(uint8_t* h_0, uint8_t* h_1, uint8_t* h_2, zk_hash_512_3_ctx* ctx,
                            bf512_t x1_0, bf512_t x1_1, bf512_t x1_2) {
  if (ctx->pending) {
    ctx->h0[0] = bf512_add(bf512_mul(ctx->h0[0], ctx->s), ctx->pending_v_0);
    ctx->h1[0] = bf512_add(bf512_mul_64(ctx->h1[0], ctx->t), ctx->pending_v_0);
    ctx->h0[1] = bf512_add(bf512_mul(ctx->h0[1], ctx->s), ctx->pending_v_1);
    ctx->h1[1] = bf512_add(bf512_mul_64(ctx->h1[1], ctx->t), ctx->pending_v_1);
    ctx->h0[2] = bf512_add(bf512_mul(ctx->h0[2], ctx->s), ctx->pending_v_2);
    ctx->h1[2] = bf512_add(bf512_mul_64(ctx->h1[2], ctx->t), ctx->pending_v_2);
    ctx->pending = 0;
  }
  const bf512_t r0 = bf512_load(ctx->sd);
  const bf512_t r1 = bf512_load(ctx->sd + BF512_NUM_BYTES);

  bf512_store(h_0,
              bf512_add(bf512_add(bf512_mul(r0, ctx->h0[0]), bf512_mul(r1, ctx->h1[0])), x1_0));
  bf512_store(h_1,
              bf512_add(bf512_add(bf512_mul(r0, ctx->h0[1]), bf512_mul(r1, ctx->h1[1])), x1_1));
  bf512_store(h_2,
              bf512_add(bf512_add(bf512_mul(r0, ctx->h0[2]), bf512_mul(r1, ctx->h1[2])), x1_2));
}
