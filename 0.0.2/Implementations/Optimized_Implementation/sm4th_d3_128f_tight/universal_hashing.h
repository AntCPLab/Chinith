/* Retain only the instance field and transcript lanes reached by sign/verify. */
/*
 *  This file implements the universal hashing functions.
 * We use multiple lanes of hashing to amortize the cost of field multiplications, and also provide precomputation for the case where the same seed is used for multiple hashes.
 */

#ifndef UNIVERSAL_HASHING_H
#define UNIVERSAL_HASHING_H

#include <stdint.h>

#include "macros.h"
#include "fields.h"

/* x0_bits is ell_hat - lambda_f - B; the suffix is the final lambda_f+B bits. */
void vole_hash(uint8_t* h, const uint8_t* sd, const uint8_t* x, unsigned int x0_bits, uint32_t lambda);
void vole_hash_2(uint8_t* h0, uint8_t* h1, const uint8_t* sd, const uint8_t* x0,
                 const uint8_t* x1, unsigned int x0_bits, uint32_t lambda);
void vole_hash_4(uint8_t* h0, uint8_t* h1, uint8_t* h2, uint8_t* h3,
                 const uint8_t* sd, const uint8_t* x0, const uint8_t* x1,
                 const uint8_t* x2, const uint8_t* x3, unsigned int x0_bits, uint32_t lambda);

typedef struct {
  const uint8_t* sd;
  uint32_t lambda;
  unsigned int x0_bits;
  unsigned int length_lambda;
  unsigned int lambda_bytes;
  size_t total_words;
  size_t last_bytes;
  bf64_t* t_pows;
  bf160_t* s_pows_160;
} vole_hash_precomp_t;

int vole_hash_precompute_init(vole_hash_precomp_t* ctx, const uint8_t* sd, unsigned int x0_bits,
                              uint32_t lambda);
void vole_hash_precompute_clear(vole_hash_precomp_t* ctx);
void vole_hash_precomp(uint8_t* h0, const vole_hash_precomp_t* ctx, const uint8_t* x0);
void vole_hash_2_precomp(uint8_t* h0, uint8_t* h1, const vole_hash_precomp_t* ctx,
                         const uint8_t* x0, const uint8_t* x1);
void vole_hash_4_precomp(uint8_t* h0, uint8_t* h1, uint8_t* h2, uint8_t* h3,
                         const vole_hash_precomp_t* ctx, const uint8_t* x0, const uint8_t* x1,
                         const uint8_t* x2, const uint8_t* x3);

typedef struct {
  bf160_t h0;
  bf160_t h1;
  bf160_t s;
  bf160_t s2;
  bf64_t t;
  const uint8_t* sd;
  bf160_t pending_v;
  int pending;
} zk_hash_160_ctx;

void zk_hash_160_init(zk_hash_160_ctx* ctx, const uint8_t* sd);
void zk_hash_160_update(zk_hash_160_ctx* ctx, bf160_t v);
void zk_hash_160_finalize(uint8_t* h, zk_hash_160_ctx* ctx, bf160_t x1);

typedef struct {
  bf160_t h0[3];
  bf160_t h1[3];
  bf160_t s;
  bf160_t s2;
  bf160_t s3;
  bf160_t s4;
  bf64_t t;
  const uint8_t* sd;
  bf160_t pending_v_0;
  bf160_t pending_v_1;
  bf160_t pending_v_2;
  bf160_t pending2_v_0;
  bf160_t pending2_v_1;
  bf160_t pending2_v_2;
  bf160_t pending3_v_0;
  bf160_t pending3_v_1;
  bf160_t pending3_v_2;
  int pending;      /* number of buffered updates, 0..3 */
} zk_hash_160_3_ctx;

void zk_hash_160_3_init(zk_hash_160_3_ctx* ctx, const uint8_t* sd);
void zk_hash_160_3_update(zk_hash_160_3_ctx* ctx, bf160_t v_0, bf160_t v_1,
                          bf160_t v_2);
void zk_hash_160_3_finalize(uint8_t* h_0, uint8_t* h_1, uint8_t* h_2,
                            zk_hash_160_3_ctx* ctx, bf160_t x1_0, bf160_t x1_1,
                            bf160_t x1_2);

#endif
