/* Unused signature-independent helpers were removed; active backend entrypoints remain. */
/* Retain only the instance field and transcript lanes reached by sign/verify. */
#include "params.h"
#include "universal_hashing.h"
#include "utils.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

// compute h1 family in VOLE hash
// _2, _4 means compute 2 or 4 at once
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

int vole_hash_precompute_init(vole_hash_precomp_t* ctx, const uint8_t* sd, unsigned int x0_bits,
                              uint32_t lambda) {
  if (!ctx || !sd) {
    return 0;
  }

  memset(ctx, 0, sizeof(*ctx));
  if (lambda != 160u) {
    return 0;
  }
  ctx->sd = sd;
  ctx->lambda = lambda;
  /* Precompute using the same prefix split as scalar and batch hashes. */
  ctx->x0_bits = x0_bits;
  ctx->lambda_bytes = ctx->lambda / 8u;
  ctx->length_lambda = (x0_bits + ctx->lambda - 1u) / ctx->lambda;
  ctx->last_bytes = (x0_bits % ctx->lambda == 0u)
                        ? ctx->lambda_bytes
                        : (x0_bits % ctx->lambda) / 8u;
  ctx->total_words = ((size_t)ctx->length_lambda * ctx->lambda_bytes + 7u) / 8u;

  ctx->t_pows = malloc(ctx->total_words * sizeof(*ctx->t_pows));
  if (!ctx->t_pows) {
    return 0;
  }

  {
    const uint8_t* t = sd + 5u * ctx->lambda_bytes;
    const bf64_t b_t = bf64_load(t);
    bf64_t running_t = bf64_one();
    for (size_t i = 0; i < ctx->total_words; ++i, running_t = bf64_mul(running_t, b_t)) {
      ctx->t_pows[i] = running_t;
    }
  }

  if (ctx->length_lambda > 1u) {
    const size_t pcount = (size_t)ctx->length_lambda - 1u;
    const uint8_t* s = sd + 4u * ctx->lambda_bytes;
    /* The instance has lambda_f=160 for every public parameter set. */
    ctx->s_pows_160 = malloc(pcount * sizeof(*ctx->s_pows_160));
    if (!ctx->s_pows_160) {
      vole_hash_precompute_clear(ctx);
      return 0;
    }
    bf160_t running_s = bf160_load(s);
    const bf160_t b_s = running_s;
    for (size_t i = 0; i < pcount; ++i, running_s = bf160_mul(running_s, b_s)) {
      ctx->s_pows_160[i] = running_s;
    }

  }

  return 1;
}

void vole_hash_precompute_clear(vole_hash_precomp_t* ctx) {
  if (!ctx) {
    return;
  }
  free(ctx->t_pows);
  free(ctx->s_pows_160);
  memset(ctx, 0, sizeof(*ctx));
}

static void vole_hash_160_4_precomp(uint8_t* h0_out, uint8_t* h1_out, uint8_t* h2_out,
                                    uint8_t* h3_out, const vole_hash_precomp_t* ctx,
                                    const uint8_t* x0, const uint8_t* x1, const uint8_t* x2,
                                    const uint8_t* x3) {
  const uint8_t* r0 = ctx->sd;
  const uint8_t* r1 = ctx->sd + 1 * BF160_NUM_BYTES;
  const uint8_t* r2 = ctx->sd + 2 * BF160_NUM_BYTES;
  const uint8_t* r3 = ctx->sd + 3 * BF160_NUM_BYTES;
  /* Keep the padded prefix and final mask slice disjoint. */
  const uint8_t* x0_tail = x0 + ctx->x0_bits / 8;
  /* Keep the padded prefix and final mask slice disjoint. */
  const uint8_t* x1_tail = x1 + ctx->x0_bits / 8;
  /* Keep the padded prefix and final mask slice disjoint. */
  const uint8_t* x2_tail = x2 + ctx->x0_bits / 8;
  /* Keep the padded prefix and final mask slice disjoint. */
  const uint8_t* x3_tail = x3 + ctx->x0_bits / 8;

  uint8_t tmp0[BF160_NUM_BYTES] = {0};
  uint8_t tmp1[BF160_NUM_BYTES] = {0};
  uint8_t tmp2[BF160_NUM_BYTES] = {0};
  uint8_t tmp3[BF160_NUM_BYTES] = {0};
  memcpy(tmp0, x0 + (size_t)(ctx->length_lambda - 1u) * BF160_NUM_BYTES, ctx->last_bytes);
  memcpy(tmp1, x1 + (size_t)(ctx->length_lambda - 1u) * BF160_NUM_BYTES, ctx->last_bytes);
  memcpy(tmp2, x2 + (size_t)(ctx->length_lambda - 1u) * BF160_NUM_BYTES, ctx->last_bytes);
  memcpy(tmp3, x3 + (size_t)(ctx->length_lambda - 1u) * BF160_NUM_BYTES, ctx->last_bytes);
  bf160_t h0_0 = bf160_load(tmp0);
  bf160_t h0_1 = bf160_load(tmp1);
  bf160_t h0_2 = bf160_load(tmp2);
  bf160_t h0_3 = bf160_load(tmp3);

  for (unsigned int i = 1; i != ctx->length_lambda; ++i) {
    const size_t off = (size_t)(ctx->length_lambda - 1u - i) * BF160_NUM_BYTES;
    const bf160_t coeff = ctx->s_pows_160[i - 1u];
    h0_0 = bf160_add(h0_0, bf160_mul(coeff, bf160_load(x0 + off)));
    h0_1 = bf160_add(h0_1, bf160_mul(coeff, bf160_load(x1 + off)));
    h0_2 = bf160_add(h0_2, bf160_mul(coeff, bf160_load(x2 + off)));
    h0_3 = bf160_add(h0_3, bf160_mul(coeff, bf160_load(x3 + off)));
  }

  bf64_t h1_0;
  bf64_t h1_1;
  bf64_t h1_2;
  bf64_t h1_3;
  compute_h1_4_precomp(ctx, x0, x1, x2, x3, &h1_0, &h1_1, &h1_2, &h1_3);
  const bf160_t br0 = bf160_load(r0);
  const bf160_t br1 = bf160_load(r1);
  const bf160_t br2 = bf160_load(r2);
  const bf160_t br3 = bf160_load(r3);

  bf160_t hh2_0 = bf160_add(bf160_mul(br0, h0_0), bf160_mul_64(br1, h1_0));
  bf160_t hh3_0 = bf160_add(bf160_mul(br2, h0_0), bf160_mul_64(br3, h1_0));
  bf160_t hh2_1 = bf160_add(bf160_mul(br0, h0_1), bf160_mul_64(br1, h1_1));
  bf160_t hh3_1 = bf160_add(bf160_mul(br2, h0_1), bf160_mul_64(br3, h1_1));
  bf160_t hh2_2 = bf160_add(bf160_mul(br0, h0_2), bf160_mul_64(br1, h1_2));
  bf160_t hh3_2 = bf160_add(bf160_mul(br2, h0_2), bf160_mul_64(br3, h1_2));
  bf160_t hh2_3 = bf160_add(bf160_mul(br0, h0_3), bf160_mul_64(br1, h1_3));
  bf160_t hh3_3 = bf160_add(bf160_mul(br2, h0_3), bf160_mul_64(br3, h1_3));

  bf160_store(h0_out, hh2_0);
  bf160_store(tmp0, hh3_0);
  memcpy(h0_out + BF160_NUM_BYTES, tmp0, UNIVERSAL_HASH_B);
  xor_u8_array(h0_out, x0_tail, h0_out, BF160_NUM_BYTES + UNIVERSAL_HASH_B);

  bf160_store(h1_out, hh2_1);
  bf160_store(tmp1, hh3_1);
  memcpy(h1_out + BF160_NUM_BYTES, tmp1, UNIVERSAL_HASH_B);
  xor_u8_array(h1_out, x1_tail, h1_out, BF160_NUM_BYTES + UNIVERSAL_HASH_B);

  bf160_store(h2_out, hh2_2);
  bf160_store(tmp2, hh3_2);
  memcpy(h2_out + BF160_NUM_BYTES, tmp2, UNIVERSAL_HASH_B);
  xor_u8_array(h2_out, x2_tail, h2_out, BF160_NUM_BYTES + UNIVERSAL_HASH_B);

  bf160_store(h3_out, hh2_3);
  bf160_store(tmp3, hh3_3);
  memcpy(h3_out + BF160_NUM_BYTES, tmp3, UNIVERSAL_HASH_B);
  xor_u8_array(h3_out, x3_tail, h3_out, BF160_NUM_BYTES + UNIVERSAL_HASH_B);
}

void vole_hash_4_precomp(uint8_t* h0, uint8_t* h1, uint8_t* h2, uint8_t* h3,
                         const vole_hash_precomp_t* ctx, const uint8_t* x0, const uint8_t* x1,
                         const uint8_t* x2, const uint8_t* x3) {
  /* Keep only this instance's 160-bit VOLEHash branch. */
  assert(ctx->lambda == 160u);
  vole_hash_160_4_precomp(h0, h1, h2, h3, ctx, x0, x1, x2, x3);
}

void vole_hash_2_precomp(uint8_t* h0, uint8_t* h1, const vole_hash_precomp_t* ctx,
                         const uint8_t* x0, const uint8_t* x1) {
  const size_t out_bytes = (size_t)ctx->lambda_bytes + UNIVERSAL_HASH_B;
  uint8_t throw2[out_bytes];
  uint8_t throw3[out_bytes];
  vole_hash_4_precomp(h0, h1, throw2, throw3, ctx, x0, x1, x0, x1);
}

void vole_hash_precomp(uint8_t* h0, const vole_hash_precomp_t* ctx, const uint8_t* x0) {
  const size_t out_bytes = (size_t)ctx->lambda_bytes + UNIVERSAL_HASH_B;
  uint8_t throw1[out_bytes];
  uint8_t throw2[out_bytes];
  uint8_t throw3[out_bytes];
  vole_hash_4_precomp(h0, throw1, throw2, throw3, ctx, x0, x0, x0, x0);
}

static void vole_hash_160_4(uint8_t* h0, uint8_t* h1, uint8_t* h2, uint8_t* h3,
                            const uint8_t* sd, const uint8_t* x0, const uint8_t* x1,
                            const uint8_t* x2, const uint8_t* x3, unsigned int x0_bits) {
  vole_hash_precomp_t ctx;
  if (!vole_hash_precompute_init(&ctx, sd, x0_bits, 160u)) {
    abort();
  }
  vole_hash_4_precomp(h0, h1, h2, h3, &ctx, x0, x1, x2, x3);
  vole_hash_precompute_clear(&ctx);
}

void vole_hash(uint8_t* h, const uint8_t* sd, const uint8_t* x, unsigned int x0_bits, uint32_t lambda) {
  /* Keep only this instance's 160-bit VOLEHash branch. */
  assert(lambda == 160u);
  vole_hash_precomp_t ctx;
  if (!vole_hash_precompute_init(&ctx, sd, x0_bits, lambda)) abort();
  vole_hash_precomp(h, &ctx, x);
  vole_hash_precompute_clear(&ctx);
}

void vole_hash_2(uint8_t* h0, uint8_t* h1, const uint8_t* sd, const uint8_t* x0,
                 const uint8_t* x1, unsigned int x0_bits, uint32_t lambda) {
  /* Keep only this instance's 160-bit VOLEHash branch. */
  assert(lambda == 160u);
  (void)lambda;
  uint8_t throw2[BF160_NUM_BYTES + UNIVERSAL_HASH_B];
  uint8_t throw3[BF160_NUM_BYTES + UNIVERSAL_HASH_B];
  vole_hash_160_4(h0, h1, throw2, throw3, sd, x0, x1, x0, x1, x0_bits);
}

void vole_hash_4(uint8_t* h0, uint8_t* h1, uint8_t* h2, uint8_t* h3,
                 const uint8_t* sd, const uint8_t* x0, const uint8_t* x1,
                 const uint8_t* x2, const uint8_t* x3, unsigned int x0_bits, uint32_t lambda) {
  /* Keep only this instance's 160-bit VOLEHash branch. */
  assert(lambda == 160u);
  (void)lambda;
  vole_hash_160_4(h0, h1, h2, h3, sd, x0, x1, x2, x3, x0_bits);
}

/* Two-step Horner: buffer every other value to perform h = h*s^2 + v_prev*s + v
 * with a single s^2 multiply instead of two s multiplies. */

void zk_hash_160_init(zk_hash_160_ctx* ctx, const uint8_t* sd) {
  const uint8_t* s = sd + 2 * BF160_NUM_BYTES;
  const uint8_t* t = sd + 3 * BF160_NUM_BYTES;

  ctx->h0      = bf160_zero();
  ctx->h1      = bf160_zero();
  ctx->s       = bf160_load(s);
  ctx->s2      = bf160_sqr(ctx->s);
  ctx->t       = bf64_load(t);
  ctx->sd      = sd;
  ctx->pending = 0;
}

void zk_hash_160_update(zk_hash_160_ctx* ctx, bf160_t v) {
  if (!ctx->pending) {
    ctx->pending_v = v;
    ctx->pending   = 1;
  } else {
    ctx->h0 = bf160_add(bf160_add(bf160_mul(ctx->h0, ctx->s2),
                                   bf160_mul(ctx->pending_v, ctx->s)), v);
    ctx->h1 = bf160_add(bf160_mul_64(
                 bf160_add(bf160_mul_64(ctx->h1, ctx->t), ctx->pending_v),
                 ctx->t), v);
    ctx->pending = 0;
  }
}

void zk_hash_160_finalize(uint8_t* h, zk_hash_160_ctx* ctx, bf160_t x1) {
  if (ctx->pending) {
    ctx->h0 = bf160_add(bf160_mul(ctx->h0, ctx->s), ctx->pending_v);
    ctx->h1 = bf160_add(bf160_mul_64(ctx->h1, ctx->t), ctx->pending_v);
    ctx->pending = 0;
  }
  const uint8_t* r0 = ctx->sd;
  const uint8_t* r1 = ctx->sd + BF160_NUM_BYTES;

  bf160_store(h, bf160_add(bf160_add(bf160_mul(bf160_load(r0), ctx->h0),
                                     bf160_mul(bf160_load(r1), ctx->h1)),
                           x1));
}

void zk_hash_160_2_init(zk_hash_160_2_ctx* ctx, const uint8_t* sd) {
  const uint8_t* s = sd + 2 * BF160_NUM_BYTES;
  const uint8_t* t = sd + 3 * BF160_NUM_BYTES;

  ctx->h0[0] = bf160_zero();
  ctx->h0[1] = bf160_zero();
  ctx->h1[0] = bf160_zero();
  ctx->h1[1] = bf160_zero();
  ctx->s     = bf160_load(s);
  ctx->s2    = bf160_sqr(ctx->s);
  ctx->t     = bf64_load(t);
  ctx->sd    = sd;
  ctx->pending = 0;
}

void zk_hash_160_2_update(zk_hash_160_2_ctx* ctx, bf160_t v_0, bf160_t v_1) {
  if (!ctx->pending) {
    ctx->pending_v_0 = v_0;
    ctx->pending_v_1 = v_1;
    ctx->pending     = 1;
  } else {
    ctx->h0[0] = bf160_add(bf160_add(bf160_mul(ctx->h0[0], ctx->s2),
                                      bf160_mul(ctx->pending_v_0, ctx->s)), v_0);
    ctx->h1[0] = bf160_add(bf160_mul_64(
                   bf160_add(bf160_mul_64(ctx->h1[0], ctx->t), ctx->pending_v_0),
                   ctx->t), v_0);
    ctx->h0[1] = bf160_add(bf160_add(bf160_mul(ctx->h0[1], ctx->s2),
                                      bf160_mul(ctx->pending_v_1, ctx->s)), v_1);
    ctx->h1[1] = bf160_add(bf160_mul_64(
                   bf160_add(bf160_mul_64(ctx->h1[1], ctx->t), ctx->pending_v_1),
                   ctx->t), v_1);
    ctx->pending = 0;
  }
}

void zk_hash_160_2_finalize(uint8_t* h_0, uint8_t* h_1, zk_hash_160_2_ctx* ctx,
                            bf160_t x1_0, bf160_t x1_1) {
  if (ctx->pending) {
    ctx->h0[0] = bf160_add(bf160_mul(ctx->h0[0], ctx->s), ctx->pending_v_0);
    ctx->h1[0] = bf160_add(bf160_mul_64(ctx->h1[0], ctx->t), ctx->pending_v_0);
    ctx->h0[1] = bf160_add(bf160_mul(ctx->h0[1], ctx->s), ctx->pending_v_1);
    ctx->h1[1] = bf160_add(bf160_mul_64(ctx->h1[1], ctx->t), ctx->pending_v_1);
    ctx->pending = 0;
  }
  const bf160_t r0 = bf160_load(ctx->sd);
  const bf160_t r1 = bf160_load(ctx->sd + BF160_NUM_BYTES);

  bf160_store(h_0,
              bf160_add(bf160_add(bf160_mul(r0, ctx->h0[0]), bf160_mul(r1, ctx->h1[0])), x1_0));
  bf160_store(h_1,
              bf160_add(bf160_add(bf160_mul(r0, ctx->h0[1]), bf160_mul(r1, ctx->h1[1])), x1_1));
}

