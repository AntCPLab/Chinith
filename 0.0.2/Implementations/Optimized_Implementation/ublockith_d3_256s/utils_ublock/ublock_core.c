/* uBlock-256/256, 24 rounds.
 * Default: Boolean S-box and explicit linear diffusion in every round.
 * REF_USE_LOOKUP_TABLES=1 restores the legacy performance path; that path
 * uses secret-indexed tables in middle rounds and is not cache resistant.
 */

#include "ublock.h"
#include "../compat.h"
#include "ublock_internal.h"
#include "utils.h"
#include <string.h>
#include <stdint.h>

/* ================================================================== *
 *  Low-level helpers                                                  *
 * ================================================================== */

/* ================================================================== *
 *  T-box tables: fuse S-box + linear layer into 8 x 256 uint64_t    *
 *                                                                     *
 *  TA0..TA3[v] = contribution of byte v at position 0..3 of X0 word  *
 *  TB0..TB3[v] = contribution of byte v at position 0..3 of X1 word  *
 *  Each entry packs (a_out << 32 | b_out) as uint64_t.               *
 * ================================================================== */

#if REF_USE_LOOKUP_TABLES
static uint64_t UBLOCK_TA0[256], UBLOCK_TA1[256], UBLOCK_TA2[256], UBLOCK_TA3[256];
static uint64_t UBLOCK_TB0[256], UBLOCK_TB1[256], UBLOCK_TB2[256], UBLOCK_TB3[256];

static void ublock_tbox_init_initialize(void)
{

    uint64_t *ta[4] = { UBLOCK_TA0, UBLOCK_TA1, UBLOCK_TA2, UBLOCK_TA3 };
    uint64_t *tb[4] = { UBLOCK_TB0, UBLOCK_TB1, UBLOCK_TB2, UBLOCK_TB3 };

    for (int v = 0; v < 256; v++) {
        uint8_t s = (uint8_t)((UBLOCK_SBOX_NIBBLE[(v >> 4) & 0x0f] << 4)
                            | UBLOCK_SBOX_NIBBLE[v & 0x0f]);

        for (int pos = 0; pos < 4; pos++) {
            unsigned shift = 24 - 8 * (unsigned)pos;

            /* TA: byte s at position pos in the A (X0) word, B = 0 */
            {
                uint32_t a = (uint32_t)s << shift;
                uint32_t b = 0;
                b ^= a;
                a ^= rotl32_u(b, 4);
                b ^= rotl32_u(a, 8);
                a ^= rotl32_u(b, 8);
                b ^= rotl32_u(a, 20);
                a ^= b;
                ta[pos][v] = ((uint64_t)a << 32) | (uint64_t)b;
            }

            /* TB: A = 0, byte s at position pos in the B (X1) word */
            {
                uint32_t a = 0;
                uint32_t b = (uint32_t)s << shift;
                b ^= a;
                a ^= rotl32_u(b, 4);
                b ^= rotl32_u(a, 8);
                a ^= rotl32_u(b, 8);
                b ^= rotl32_u(a, 20);
                a ^= b;
                tb[pos][v] = ((uint64_t)a << 32) | (uint64_t)b;
            }
        }
    }
}

/* Serialize first initialization and publish the read-only table. */
static void ublock_tbox_init(void) {
  static ref_once_t once = REF_ONCE_INIT;
  ref_call_once(&once, ublock_tbox_init_initialize);
}

/* ================================================================== *
 *  Byte permutations PL_256 / PR_256  (hardcoded word-level)         *
 *                                                                     *
 *  Input: 4 uint32_t words w0..w3 (big-endian byte order).           *
 *  byte0(w) = w>>24, byte1(w) = (w>>16)&0xFF, etc.                  *
 * ================================================================== */

/* ================================================================== *
 *  ublock256_round_w — fast round function (T-box path)              *
 *                                                                     *
 *  Fuses S-box substitution + linear diffusion into 8 table lookups  *
 *  per word-pair (analogous to SM4_T() in OpenSSL's sm4.c).          *
 *  Each of the 8 tables spans 256 × 8 B = 2 KB (16 cache lines);     *
 *  the index directly depends on rk XOR state, so cache-timing        *
 *  attacks may observe which cache line is touched, including in      *
 *  middle rounds. This optional legacy path is not cache resistant.   *
 * ================================================================== */

// for portable C and rotl32_u, we use unint32_t arrays 
static inline void ublock256_round_w(uint32_t X0[4], uint32_t X1[4],
                                      const uint32_t rki[8])
{
    uint32_t ow0[4], ow1[4];

    for (int w = 0; w < 4; w++) {
        uint32_t a = X0[w] ^ rki[w];
        uint32_t b = X1[w] ^ rki[w + 4];

        uint64_t t = UBLOCK_TA0[(a >> 24)       ]
                   ^ UBLOCK_TA1[(a >> 16) & 0xFF]
                   ^ UBLOCK_TA2[(a >>  8) & 0xFF]
                   ^ UBLOCK_TA3[(a      ) & 0xFF]
                   ^ UBLOCK_TB0[(b >> 24)       ]
                   ^ UBLOCK_TB1[(b >> 16) & 0xFF]
                   ^ UBLOCK_TB2[(b >>  8) & 0xFF]
                   ^ UBLOCK_TB3[(b      ) & 0xFF];

        ow0[w] = (uint32_t)(t >> 32);
        ow1[w] = (uint32_t) t;
    }

    ublock_perm_PL(X0, ow0);
    ublock_perm_PR(X1, ow1);
}
#else
static void ublock_tbox_init(void) { }
#endif


/* Explicit diffusion. Substitution follows the selected build mode. */
static inline void ublock256_round_slow(uint32_t X0[4], uint32_t X1[4],
                                         const uint32_t rki[8])
{
    uint32_t ow0[4], ow1[4];

    for (int w = 0; w < 4; w++) {
        uint32_t a = X0[w] ^ rki[w];
        uint32_t b = X1[w] ^ rki[w + 4];

        /* Boolean substitution by default; optional legacy byte table. */
        a = ((uint32_t)ublock_sub_byte(a >> 24)         << 24)
          | ((uint32_t)ublock_sub_byte((a >> 16) & 0xFF) << 16)
          | ((uint32_t)ublock_sub_byte((a >>  8) & 0xFF) <<  8)
          |  (uint32_t)ublock_sub_byte( a         & 0xFF);

        b = ((uint32_t)ublock_sub_byte(b >> 24)         << 24)
          | ((uint32_t)ublock_sub_byte((b >> 16) & 0xFF) << 16)
          | ((uint32_t)ublock_sub_byte((b >>  8) & 0xFF) <<  8)
          |  (uint32_t)ublock_sub_byte( b         & 0xFF);

        /* Linear mixing layer (same sequence as T-box construction) */
        b ^= a;
        a ^= rotl32_u(b,  4);
        b ^= rotl32_u(a,  8);
        a ^= rotl32_u(b,  8);
        b ^= rotl32_u(a, 20);
        a ^= b;

        ow0[w] = a;
        ow1[w] = b;
    }

    ublock_perm_PL(X0, ow0);
    ublock_perm_PR(X1, ow1);
}
#if !REF_USE_LOOKUP_TABLES
#define ublock256_round_w ublock256_round_slow
#endif


/* ================================================================== *
 *  Key-schedule helpers (unchanged algorithm, byte-level)             *
 * ================================================================== */

static void apply_nibble_perm(uint8_t *dst, const uint8_t *src,
                               const uint8_t *perm, size_t total_nibbles)
{
    uint8_t nib[64], out_nib[64];
    size_t nbytes = (total_nibbles + 1) / 2;
    for (size_t i = 0; i < nbytes; i++) {
        nib[2*i]   = (src[i] >> 4) & 0x0f;
        nib[2*i+1] =  src[i]       & 0x0f;
    }
    for (size_t j = 0; j < total_nibbles; j++)
        out_nib[j] = nib[perm[j]];
    for (size_t i = 0; i < nbytes; i++)
        dst[i] = (uint8_t)((out_nib[2*i] << 4) | out_nib[2*i+1]);
}

static inline uint8_t gf24_mul2(uint8_t b)
{
    const uint8_t mask = (uint8_t)(0u - ((b >> 3) & 1u));
    return (uint8_t)(((b << 1) ^ (mask & 0x03u)) & 0x0fu);
}

static void apply_tk(uint8_t *data, size_t nbytes)
{
    for (size_t i = 0; i < nbytes; i++) {
        uint8_t hi = (data[i] >> 4) & 0x0f;
        uint8_t lo =  data[i]       & 0x0f;
        data[i] = (uint8_t)((gf24_mul2(hi) << 4) | gf24_mul2(lo));
    }
}

/* ================================================================== *
 *  uBlock-256/256 key schedule                                        *
 *                                                                     *
 *  Computation unchanged; final round keys stored as uint32_t[8].     *
 * ================================================================== */

static void store_rk(uint32_t rk[8],
                     const uint8_t K0[8], const uint8_t K1[8],
                     const uint8_t K2[8], const uint8_t K3[8])
{
    rk[0] = load_u32_be(K0, 0); rk[1] = load_u32_be(K0, 1);
    rk[2] = load_u32_be(K1, 0); rk[3] = load_u32_be(K1, 1);
    rk[4] = load_u32_be(K2, 0); rk[5] = load_u32_be(K2, 1);
    rk[6] = load_u32_be(K3, 0); rk[7] = load_u32_be(K3, 1);
}

int ublock256_set_key(const uint8_t key[32], ublock256_key_t *ks)
{
    if (!key || !ks) return -1;

    ublock_tbox_init();

    uint8_t K0[8], K1[8], K2[8], K3[8];
    memcpy(K0, key +  0, 8);
    memcpy(K1, key +  8, 8);
    memcpy(K2, key + 16, 8);
    memcpy(K3, key + 24, 8);

    store_rk(ks->rk[0], K0, K1, K2, K3);

    for (int i = 1; i <= UBLOCK_ROUNDS; i++) {
        /* K0||K1 <- pk(K0||K1) */
        {
            uint8_t tmp[16];
            memcpy(tmp + 0, K0, 8);
            memcpy(tmp + 8, K1, 8);
            // Apply nibble permutation pk to K0||K1, by nibbles, 32 is #nibbles
            apply_nibble_perm(tmp, tmp, pk, 32);
            memcpy(K0, tmp + 0, 8);
            memcpy(K1, tmp + 8, 8);
        }

        /* K2 <- K2 XOR Sk(K0 XOR RC_i) */
        {
            uint8_t tmp[8];
            uint32_t rc = UBLOCK_RC[i - 1];
            memcpy(tmp, K0, 8);
            tmp[0] ^= (uint8_t)(rc >> 24);
            tmp[1] ^= (uint8_t)(rc >> 16);
            tmp[2] ^= (uint8_t)(rc >>  8);
            tmp[3] ^= (uint8_t) rc;
            // Apply the byte-wise S-box to tmp, which is K0 XOR RC_i
            ublock_apply_sn(tmp, 8);
            xor_u8_array(K2, tmp, K2, 8);
        }

        /* K3 <- K3 XOR Tk(K1) */
        {
            uint8_t tmp[8];
            memcpy(tmp, K1, 8);
            apply_tk(tmp, 8);
            xor_u8_array(K3, tmp, K3, 8);
        }

        /* K <- K2||K3||K1||K0 */
        /* K0||K1||K2||K3 <- K */
        {
            uint8_t nK0[8], nK1[8], nK2[8], nK3[8];
            memcpy(nK0, K2, 8); memcpy(nK1, K3, 8);
            memcpy(nK2, K1, 8); memcpy(nK3, K0, 8);
            memcpy(K0, nK0, 8); memcpy(K1, nK1, 8);
            memcpy(K2, nK2, 8); memcpy(K3, nK3, 8);
        }

        store_rk(ks->rk[i], K0, K1, K2, K3);
    }
    return 0;
}

/* Every round uses the Boolean path unless lookup tables are opted in. */
void ublock256_256_encrypt(const uint8_t in[32], uint8_t out[32],
                           const ublock256_key_t *ks)
{
    uint32_t X0[4], X1[4];

    for (int w = 0; w < 4; w++) {
        X0[w] = load_u32_be(in, (uint32_t)w);
        X1[w] = load_u32_be(in + 16, (uint32_t)w);
    }

    /* First round: slow path (plaintext known to attacker) */
    ublock256_round_slow(X0, X1, ks->rk[0]);

    /* Middle rounds: selected arithmetic or legacy T-box path. */
    for (int i = 1; i < UBLOCK_ROUNDS - 1; i++)
        ublock256_round_w(X0, X1, ks->rk[i]);

    /* Last round: slow path (ciphertext known to attacker) */
    ublock256_round_slow(X0, X1, ks->rk[UBLOCK_ROUNDS - 1]);

    for (int w = 0; w < 4; w++) {
        store_u32_be(X0[w] ^ ks->rk[UBLOCK_ROUNDS][w], out + 4 * w);
        store_u32_be(X1[w] ^ ks->rk[UBLOCK_ROUNDS][w + 4], out + 16 + 4 * w);
    }
}
