#include "vistrutith_constraints.h"

#include "../utils.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

/*
 * vi-SBox affine coefficients zeta_0..zeta_8 in GF(2^512).
 *
 * Derivation:
 * 1) Write AES affine map as a linearized polynomial over GF(2^8):
 *      A(z) = chi_8 + sum_{k=0}^7 chi_k * z^(2^k),
 *    where (chi_0..chi_7) = (0x05,0x09,0xf9,0x25,0xf4,0x01,0xb5,0x8f)
 *    and chi_8 = 0x63.
 * 2) Embed each byte coefficient into GF(2^512) with the vi-compatible map:
 *      zeta_k = bf512_byte_combine_bits(chi_k), k=0..8.
 * 3) Materialize zeta_k as BF512 constants below.
 */
static const bf512_t vistrutith_sbox_affine_coeffs[9] = {
    BF512C(UINT64_C(0xe76ef44d9176df23), UINT64_C(0x7d1fb2306449111b),
           UINT64_C(0xd345568e76e43bfd), UINT64_C(0x0058b1372714488a),
           UINT64_C(0x5abe43a7a38b5ce7), UINT64_C(0xa8fac14641908164),
           UINT64_C(0x8b453f58ecaa6860), UINT64_C(0x90b4b2bd7d5eb34b)),
    BF512C(UINT64_C(0x5de7a890b1db560a), UINT64_C(0xb6da7d8cfc4655b2),
           UINT64_C(0x450a93e2819878ff), UINT64_C(0xe313e7568f4207d9),
           UINT64_C(0xd4b359f402b8ca64), UINT64_C(0xa2e2a68fd71ad70b),
           UINT64_C(0x649911d470a0dd8e), UINT64_C(0x115c71b3ad136af6)),
    BF512C(UINT64_C(0xbcabdb6584b5854e), UINT64_C(0x5967ca5dec26babc),
           UINT64_C(0x0e50c47de8c87c57), UINT64_C(0x4e26bc7de74c1d0e),
           UINT64_C(0xfed826b695125e50), UINT64_C(0x81d9aa6bdbd748ab),
           UINT64_C(0xf8e0b245e4c545fa), UINT64_C(0x565ca04a7319b58f)),
    BF512C(UINT64_C(0xc991e1217957debc), UINT64_C(0x1726552ffa75ac69),
           UINT64_C(0x3612649e5f30209f), UINT64_C(0x6642df4c031c72ea),
           UINT64_C(0xbd965f294078bc28), UINT64_C(0xaa008f18c23ff9e6),
           UINT64_C(0xe4866f93050c33fa), UINT64_C(0x4032097db0918a00)),
    BF512C(UINT64_C(0x062287b8a4180c66), UINT64_C(0x92a205e17429fe15),
           UINT64_C(0x981f01111fb43f55), UINT64_C(0xad6dea1c4f1a525d),
           UINT64_C(0x70d53ce53421c8d3), UINT64_C(0x8bc1cda24d5d1ec4),
           UINT64_C(0x173c9cc978cff014), UINT64_C(0xd7b46344a3546c32)),
    BF512C(UINT64_C(0x0000000000000001), UINT64_C(0x0000000000000000),
           UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000),
           UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000),
           UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000)),
    BF512C(UINT64_C(0x47fb6ee6e8cedb57), UINT64_C(0xa4efa5560d520c45),
           UINT64_C(0xefaf798b2c4436fa), UINT64_C(0x38b23b8198c60cf6),
           UINT64_C(0xd199a9ff4e1d824f), UINT64_C(0x4dc8e08228276d87),
           UINT64_C(0xd95dac6af1501687), UINT64_C(0xa7874c46172889da)),
    BF512C(UINT64_C(0x75105a3735def006), UINT64_C(0xd2100f36d840d5fe),
           UINT64_C(0xf431dd18ee976463), UINT64_C(0x6592877c892da3e9),
           UINT64_C(0xb0be31d7d2b59897), UINT64_C(0xf0870f386632695a),
           UINT64_C(0x56d4848c8372baa4), UINT64_C(0xe026ec9d2b31cf89)),
    BF512C(UINT64_C(0xbe2c6ce95f077de6), UINT64_C(0x9ae5cd9950c3ada4),
           UINT64_C(0x6c593ae33089f4cf), UINT64_C(0xa3a367ec1d46b5bb),
           UINT64_C(0xde9199146c3f0b3c), UINT64_C(0x8442377402d3dcde),
           UINT64_C(0x9a4222496ffecbc2), UINT64_C(0x43820c3695af677a))};

/*
 * Squared coefficients used when sq=true:
 *   zeta_k_sq = zeta_k^2 (Frobenius square in GF(2^512)).
 *
 * They realize A(z)^2 = zeta_8^2 + sum_{k=0}^7 zeta_k^2 * z^(2^(k+1)),
 * i.e., same linearized affine map on conjugates with one-index shift.
 */
static const bf512_t vistrutith_sbox_affine_coeffs_sq[9] = {
    BF512C(UINT64_C(0x90f919f67f1ad78c), UINT64_C(0x6c8dbac200ecd3fd),
           UINT64_C(0x457d75084032d706), UINT64_C(0x884fedda543343d6),
           UINT64_C(0xca49cdd28813911c), UINT64_C(0x5de65361fea67c4b),
           UINT64_C(0xbf332bd8e4e35cfc), UINT64_C(0x654cf25cb0d9ae37)),
    BF512C(UINT64_C(0x41d9e95e4cd6d731), UINT64_C(0x364da0b7797bf250),
           UINT64_C(0x77b0789a33f009af), UINT64_C(0x95dfd19dd7dc5eab),
           UINT64_C(0xa14c951a7a3c4a9c), UINT64_C(0xc6092d20657a7343),
           UINT64_C(0xce6130a3899fe693), UINT64_C(0x70332f02b47ce5e8)),
    BF512C(UINT64_C(0x366464966a86746b), UINT64_C(0xbb8e3801d3cdf39d),
           UINT64_C(0x2dfb26e75c49ddff), UINT64_C(0x503e693dc98699fa),
           UINT64_C(0xc24b5327567bfd88), UINT64_C(0xe84b954ca596567b),
           UINT64_C(0xb0a57d79e36d1eab), UINT64_C(0x73832a4991420892)),
    BF512C(UINT64_C(0x4556b919fb40880a), UINT64_C(0xfb3c32d67fa4d876),
           UINT64_C(0x41d5faeead6a86c9), UINT64_C(0x98c1045d0fb1684e),
           UINT64_C(0x02205e15b0efadcc), UINT64_C(0x930d57d68ef921e5),
           UINT64_C(0xf14d653c18d0541b), UINT64_C(0x4411a5901927ab29)),
    BF512C(UINT64_C(0xe744943e594a74d7), UINT64_C(0xe14e2274aa5ad230),
           UINT64_C(0x1f362b752f8b0356), UINT64_C(0x4dae557a4a698487),
           UINT64_C(0xa94e0befa4542608), UINT64_C(0x73a4eb0d3e4a5973),
           UINT64_C(0xc1f766028e11a4c4), UINT64_C(0x66fcf71795e7434d)),
    BF512C(UINT64_C(0x0000000000000001), UINT64_C(0x0000000000000000),
           UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000),
           UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000),
           UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000)),
    BF512C(UINT64_C(0x5bc52f2815c35a6d), UINT64_C(0x2478786d886faba7),
           UINT64_C(0xdd1592f39e2c47aa), UINT64_C(0x4e7e0d4ac0585584),
           UINT64_C(0xa4666511369902b7), UINT64_C(0x29236b2d9a47c9cf),
           UINT64_C(0x73a58d1d086f2d9a), UINT64_C(0xc6e812f70e4706c4)),
    BF512C(UINT64_C(0x34c9b36979082736), UINT64_C(0xe45daf81a13b27ae),
           UINT64_C(0x8381a582dd676dcc), UINT64_C(0xf04d56e15ef1fd42),
           UINT64_C(0x11f2a4cda889d20b), UINT64_C(0x368e221803481a19),
           UINT64_C(0x98b5b42f0aed5c37), UINT64_C(0x9015c39f9f4d2a61)),
    BF512C(UINT64_C(0x8e40efb459a5ae1e), UINT64_C(0x2f98603d39346307),
           UINT64_C(0x15ce60ee2a1b2ece), UINT64_C(0x13060080f6a7b211),
           UINT64_C(0x9fffbe9e09ba4488), UINT64_C(0x3c9645d195c24c76),
           UINT64_C(0x77699aa396e7e9d9), UINT64_C(0x11fd00914f00f3dc))};

/*
 * MixColumns linearized coefficients over GF(2^512).
 * v1, v2, v3 correspond to multiplication by {01}, {02}, {03} in the
 * vi-compatible embedding; _sq are their Frobenius squares for sq=true.
 */
static const bf512_t vistrutith_mixcolumns_coeffs[3] = {
    BF512C(UINT64_C(0x0000000000000001), UINT64_C(0x0000000000000000),
           UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000),
           UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000),
           UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000)),
    BF512C(UINT64_C(0xd10a90dbfbf0ab48), UINT64_C(0xc6918a31b784e286),
           UINT64_C(0xfebe70692aade602), UINT64_C(0x5066d80aee92d170),
           UINT64_C(0x98f51080f5f0a16f), UINT64_C(0x40b1540ae406d71f),
           UINT64_C(0x3be042210fc776cb), UINT64_C(0xe33798f4ec1cbbd9)),
    BF512C(UINT64_C(0xd10a90dbfbf0ab49), UINT64_C(0xc6918a31b784e286),
           UINT64_C(0xfebe70692aade602), UINT64_C(0x5066d80aee92d170),
           UINT64_C(0x98f51080f5f0a16f), UINT64_C(0x40b1540ae406d71f),
           UINT64_C(0x3be042210fc776cb), UINT64_C(0xe33798f4ec1cbbd9))};

static const bf512_t vistrutith_mixcolumns_coeffs_sq[3] = {
    BF512C(UINT64_C(0x0000000000000001), UINT64_C(0x0000000000000000),
           UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000),
           UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000),
           UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000)),
    BF512C(UINT64_C(0xe76ef44d9176df22), UINT64_C(0x7d1fb2306449111b),
           UINT64_C(0xd345568e76e43bfd), UINT64_C(0x0058b1372714488a),
           UINT64_C(0x5abe43a7a38b5ce7), UINT64_C(0xa8fac14641908164),
           UINT64_C(0x8b453f58ecaa6860), UINT64_C(0x90b4b2bd7d5eb34b)),
    BF512C(UINT64_C(0xe76ef44d9176df23), UINT64_C(0x7d1fb2306449111b),
           UINT64_C(0xd345568e76e43bfd), UINT64_C(0x0058b1372714488a),
           UINT64_C(0x5abe43a7a38b5ce7), UINT64_C(0xa8fac14641908164),
           UINT64_C(0x8b453f58ecaa6860), UINT64_C(0x90b4b2bd7d5eb34b))};

/*
 * InvNormToConjugates basis constants.
 *
 * Let beta8 be the generator used by bf512_byte_combine(), and define
 *   beta4 = beta8^6 + beta8^4  (the chosen GF(2^4) basis element).
 *
 * vistrutith_beta4_squares[j] = beta4^(2^j), for j=0..4.
 * j=4 repeats j=0 because beta4^(2^4) = beta4 inside GF(2^4).
 */
static const bf512_t vistrutith_beta4_squares[5] = {
    BF512C(UINT64_C(0xd120f0a833cc00bd), UINT64_C(0x5ac01a75799721ad),
           UINT64_C(0x32cd0d9273c2dea9), UINT64_C(0x1d903c4783ef1d7d),
           UINT64_C(0x6b0558c8f22fdb80), UINT64_C(0x9bef7e419bdc0f08),
           UINT64_C(0x71521b7b6d7cba6f), UINT64_C(0x157fdd5e04a54bdf)),
    BF512C(UINT64_C(0xa0959aab79b80474), UINT64_C(0xd9f01766691b1d5e),
           UINT64_C(0x3cea2f055aa00d07), UINT64_C(0x38ea8ab6bfd2447c),
           UINT64_C(0x8b27ea58ed96dea8), UINT64_C(0xe53221c469b7ece3),
           UINT64_C(0x521893321dfa7ee7), UINT64_C(0x3733fefb6a763a91)),
    BF512C(UINT64_C(0xcb3c36de6ad98de1), UINT64_C(0x48f5c2af8883785a),
           UINT64_C(0x9868e7fbde1e90ac), UINT64_C(0xc631e090946b1652),
           UINT64_C(0x6e2fa8c3be8a93ab), UINT64_C(0x74c5384c64e1b584),
           UINT64_C(0xcc96a6c5ec8c7166), UINT64_C(0xa3a4e0abbe9ea8f3)),
    BF512C(UINT64_C(0xba895cdd20ad8929), UINT64_C(0xcbc5cfbc980f44a9),
           UINT64_C(0x964fc56cf77c4302), UINT64_C(0xe34b5661a8564f53),
           UINT64_C(0x8e0d1a53a1339683), UINT64_C(0x0a1867c9968a566f),
           UINT64_C(0xefdc2e8c9c0ab5ee), UINT64_C(0x81e8c30ed04dd9bd)),
    BF512C(UINT64_C(0xd120f0a833cc00bd), UINT64_C(0x5ac01a75799721ad),
           UINT64_C(0x32cd0d9273c2dea9), UINT64_C(0x1d903c4783ef1d7d),
           UINT64_C(0x6b0558c8f22fdb80), UINT64_C(0x9bef7e419bdc0f08),
           UINT64_C(0x71521b7b6d7cba6f), UINT64_C(0x157fdd5e04a54bdf))};

/*
 * vistrutith_beta4_cubes[j] = beta4^(3*2^j), for j=0..3.
 *
 * Together with vistrutith_beta4_squares, these constants implement
 * y_j = x0 + x1*beta4^(2^j) + x2*beta4^(2^(j+1)) + x3*beta4^(3*2^j).
 */
static const bf512_t vistrutith_beta4_cubes[4] = {
    BF512C(UINT64_C(0xba895cdd20ad8929), UINT64_C(0xcbc5cfbc980f44a9),
           UINT64_C(0x964fc56cf77c4302), UINT64_C(0xe34b5661a8564f53),
           UINT64_C(0x8e0d1a53a1339683), UINT64_C(0x0a1867c9968a566f),
           UINT64_C(0xefdc2e8c9c0ab5ee), UINT64_C(0x81e8c30ed04dd9bd)),
    BF512C(UINT64_C(0xd120f0a833cc00bd), UINT64_C(0x5ac01a75799721ad),
           UINT64_C(0x32cd0d9273c2dea9), UINT64_C(0x1d903c4783ef1d7d),
           UINT64_C(0x6b0558c8f22fdb80), UINT64_C(0x9bef7e419bdc0f08),
           UINT64_C(0x71521b7b6d7cba6f), UINT64_C(0x157fdd5e04a54bdf)),
    BF512C(UINT64_C(0xa0959aab79b80474), UINT64_C(0xd9f01766691b1d5e),
           UINT64_C(0x3cea2f055aa00d07), UINT64_C(0x38ea8ab6bfd2447c),
           UINT64_C(0x8b27ea58ed96dea8), UINT64_C(0xe53221c469b7ece3),
           UINT64_C(0x521893321dfa7ee7), UINT64_C(0x3733fefb6a763a91)),
    BF512C(UINT64_C(0xcb3c36de6ad98de1), UINT64_C(0x48f5c2af8883785a),
           UINT64_C(0x9868e7fbde1e90ac), UINT64_C(0xc631e090946b1652),
           UINT64_C(0x6e2fa8c3be8a93ab), UINT64_C(0x74c5384c64e1b584),
           UINT64_C(0xcc96a6c5ec8c7166), UINT64_C(0xa3a4e0abbe9ea8f3))};

void vistrutith_shuffle_key_prover(uint8_t fixed_key_bits[VISTRUTAH_KEY_SIZE_512],
                                   bf512_t fixed_key_tag[VISTRUTAH_KEY_SIZE_512 * 8u]) {
  bf512_t temp[(VISTRUTAH_KEY_SIZE_512 / 2u) * 8u];

  vistrutah_shuffle_key(fixed_key_bits);

  memcpy(temp, fixed_key_tag + (VISTRUTAH_KEY_SIZE_512 / 2u) * 8u, sizeof(temp));
  for (unsigned int i = 0; i < (VISTRUTAH_KEY_SIZE_512 / 2u); ++i) {
    memcpy(fixed_key_tag + (VISTRUTAH_KEY_SIZE_512 / 2u + i) * 8u,
           temp + (unsigned int)VISTRUTAH_KEXP_SHUFFLE[i] * 8u, 8u * sizeof(bf512_t));
  }
}

void vistrutith_shuffle_key_verifier(bf512_t fixed_key_key[VISTRUTAH_KEY_SIZE_512 * 8u]) {
  bf512_t temp[(VISTRUTAH_KEY_SIZE_512 / 2u) * 8u];

  memcpy(temp, fixed_key_key + (VISTRUTAH_KEY_SIZE_512 / 2u) * 8u, sizeof(temp));
  for (unsigned int i = 0; i < (VISTRUTAH_KEY_SIZE_512 / 2u); ++i) {
    memcpy(fixed_key_key + (VISTRUTAH_KEY_SIZE_512 / 2u + i) * 8u,
           temp + (unsigned int)VISTRUTAH_KEXP_SHUFFLE[i] * 8u, 8u * sizeof(bf512_t));
  }
}

void vistrutith_rotate_bytes_prover(uint8_t* fixed_key_bits, bf512_t* fixed_key_tag,
                                    int shift, int len) {
  bf512_t temp[VISTRUTAH_512_BLOCK_SIZE * 8u];

  vistrutah_rotate_bytes(fixed_key_bits, shift, len);

  assert(fixed_key_tag);
  assert(len > 0);
  assert(shift >= 0);
  assert(len <= (int)VISTRUTAH_512_BLOCK_SIZE);

  memcpy(temp, fixed_key_tag, (size_t)len * 8u * sizeof(bf512_t));
  for (int i = 0; i < len; ++i) {
    memcpy(fixed_key_tag + (size_t)i * 8u, temp + (size_t)((i + shift) % len) * 8u,
           8u * sizeof(bf512_t));
  }
}

void vistrutith_rotate_bytes_verifier(bf512_t* fixed_key_key, int shift, int len) {
  bf512_t temp[VISTRUTAH_512_BLOCK_SIZE * 8u];

  assert(fixed_key_key);
  assert(len > 0);
  assert(shift >= 0);
  assert(len <= (int)VISTRUTAH_512_BLOCK_SIZE);

  memcpy(temp, fixed_key_key, (size_t)len * 8u * sizeof(bf512_t));
  for (int i = 0; i < len; ++i) {
    memcpy(fixed_key_key + (size_t)i * 8u, temp + (size_t)((i + shift) % len) * 8u,
           8u * sizeof(bf512_t));
  }
}

void vistrutith_state_to_bytes_prover(bf512_t out_val[16], bf512_t out_tag[16],
                                      const uint8_t state_bits[16],
                                      const bf512_t state_tag[128]) {
  for (unsigned int i = 0; i < 16u; ++i) {
    out_val[i] = bf512_byte_combine_bits(state_bits[i]);
    out_tag[i] = bf512_byte_combine(state_tag + i * 8u);
  }
}

void vistrutith_state_to_bytes_verifier(bf512_t out_key[16],
                                        const bf512_t state_key[128]) {
  for (unsigned int i = 0; i < 16u; ++i) {
    out_key[i] = bf512_byte_combine(state_key + i * 8u);
  }
}

void vistrutith_state_to_conjugates_prover(bf512_t out_val[128], bf512_t out_tag[128],
                                           const uint8_t state_bits[16],
                                           const bf512_t state_tag[128]) {
  assert(out_val);
  assert(out_tag);
  assert(state_bits);
  assert(state_tag);

  for (unsigned int i = 0; i < 16u; ++i) {
    uint8_t x = state_bits[i];
    for (unsigned int j = 0; j != 7u; ++j) {
      out_val[i * 8u + j] = bf512_byte_combine_bits(x);
      x = bits_sq(x);
    }
    out_val[i * 8u + 7u] = bf512_byte_combine_bits(x);
  }

  for (unsigned int i = 0; i < 16u; ++i) {
    bf512_t x[8];
    memcpy(x, state_tag + i * 8u, sizeof(x));
    for (unsigned int j = 0; j != 7u; ++j) {
      out_tag[i * 8u + j] = bf512_byte_combine(x);
      bf512_sq_bit_inplace(x);
    }
    out_tag[i * 8u + 7u] = bf512_byte_combine(x);
  }
}

void vistrutith_state_to_conjugates_verifier(bf512_t out_key[128],
                                             const bf512_t state_key[128]) {
  assert(out_key);
  assert(state_key);

  for (unsigned int i = 0; i < 16u; ++i) {
    bf512_t x[8];
    memcpy(x, state_key + i * 8u, sizeof(x));
    for (unsigned int j = 0; j != 7u; ++j) {
      out_key[i * 8u + j] = bf512_byte_combine(x);
      bf512_sq_bit_inplace(x);
    }
    out_key[i * 8u + 7u] = bf512_byte_combine(x);
  }
}

void vistrutith_invnorm_to_conjugates_prover(bf512_t out_val[4], bf512_t out_tag[4],
                                             uint8_t x_bits, const bf512_t x_tag[4]) {
  for (unsigned int i = 0; i != 4u; ++i) {
    out_val[i] = bf512_add(
        bf512_add(bf512_from_bit(get_bit(x_bits, 0)),
                  bf512_mul_bit(vistrutith_beta4_squares[i], get_bit(x_bits, 1))),
        bf512_add(bf512_mul_bit(vistrutith_beta4_squares[i + 1u], get_bit(x_bits, 2)),
                  bf512_mul_bit(vistrutith_beta4_cubes[i], get_bit(x_bits, 3))));

    out_tag[i] = bf512_add(
        bf512_add(x_tag[0], bf512_mul(vistrutith_beta4_squares[i], x_tag[1])),
        bf512_add(bf512_mul(vistrutith_beta4_squares[i + 1u], x_tag[2]),
                  bf512_mul(vistrutith_beta4_cubes[i], x_tag[3])));
  }
}

void vistrutith_invnorm_to_conjugates_verifier(bf512_t out_key[4],
                                               const bf512_t x_key[4]) {
  for (unsigned int i = 0; i != 4u; ++i) {
    out_key[i] = bf512_add(
        bf512_add(x_key[0], bf512_mul(vistrutith_beta4_squares[i], x_key[1])),
        bf512_add(bf512_mul(vistrutith_beta4_squares[i + 1u], x_key[2]),
                  bf512_mul(vistrutith_beta4_cubes[i], x_key[3])));
  }
}

/* clarify-261002-1000_xhs1.txt item 2: place affine constants only at the commitment's top degree. */
void vistrutith_sbox_affine_prover(bf512_t* out_val, bf512_t* out_tag,
                                   const bf512_t* in_val, const bf512_t* in_tag,
                                   size_t nbytes, bool sq) {
  const bf512_t* C = sq ? vistrutith_sbox_affine_coeffs_sq : vistrutith_sbox_affine_coeffs;
  const unsigned int t = sq ? 1u : 0u;

  for (size_t i = 0; i < nbytes; ++i) {
    bf512_t acc_val = C[8];
    bf512_t acc_tag = bf512_zero();

    for (unsigned int k = 0; k < 8u; ++k) {
      const size_t idx = i * 8u + ((k + t) & 7u);
      acc_val = bf512_add(acc_val, bf512_mul(C[k], in_val[idx]));
      acc_tag = bf512_add(acc_tag, bf512_mul(C[k], in_tag[idx]));
    }
    out_val[i] = acc_val;
    out_tag[i] = acc_tag;
  }
}

void vistrutith_sbox_affine_verifier(bf512_t* out_key, const bf512_t* in_key,
                                     size_t nbytes, bool sq, bf512_t constant_scale) {
  const bf512_t* C = sq ? vistrutith_sbox_affine_coeffs_sq : vistrutith_sbox_affine_coeffs;
  const unsigned int t = sq ? 1u : 0u;
  const bf512_t affine_constant = bf512_mul(C[8], constant_scale);

  for (size_t i = 0; i < nbytes; ++i) {
    bf512_t acc_key = affine_constant;

    for (unsigned int k = 0; k < 8u; ++k) {
      const size_t idx = i * 8u + ((k + t) & 7u);
      /* clarify-261002-1000_xhs1.txt item 2: C[5] is one in both affine maps. */
      acc_key = bf512_add(acc_key, k == 5u ? in_key[idx] : bf512_mul(C[k], in_key[idx]));
    }
    out_key[i] = acc_key;
  }
}

void vistrutith_shiftrows_prover(bf512_t* out_val, bf512_t* out_tag,
                                 const bf512_t* in_val, const bf512_t* in_tag,
                                 size_t nbytes) {
  if ((nbytes & 15u) != 0u) {
    return;
  }

  for (size_t base = 0; base < nbytes; base += 16u) {
    bf512_t out_val_blk[16];
    bf512_t out_tag_blk[16];

    for (unsigned int r = 0; r < 4u; ++r) {
      for (unsigned int c = 0; c < 4u; ++c) {
        const unsigned int dst = 4u * c + r;
        const unsigned int src = 4u * ((c + r) & 3u) + r;
        out_val_blk[dst] = in_val[base + src];
        out_tag_blk[dst] = in_tag[base + src];
      }
    }

    memcpy(out_val + base, out_val_blk, sizeof(out_val_blk));
    memcpy(out_tag + base, out_tag_blk, sizeof(out_tag_blk));
  }
}

void vistrutith_shiftrows_verifier(bf512_t* out_key, const bf512_t* in_key, size_t nbytes) {
  if ((nbytes & 15u) != 0u) {
    return;
  }

  for (size_t base = 0; base < nbytes; base += 16u) {
    bf512_t out_key_blk[16];

    for (unsigned int r = 0; r < 4u; ++r) {
      for (unsigned int c = 0; c < 4u; ++c) {
        const unsigned int dst = 4u * c + r;
        const unsigned int src = 4u * ((c + r) & 3u) + r;
        out_key_blk[dst] = in_key[base + src];
      }
    }

    memcpy(out_key + base, out_key_blk, sizeof(out_key_blk));
  }
}

void vistrutith_mixcolumns_prover(bf512_t* out_val, bf512_t* out_tag,
                                  const bf512_t* in_val, const bf512_t* in_tag,
                                  size_t nbytes, bool sq) {
  if ((nbytes & 15u) != 0u) {
    return;
  }

  const bf512_t* coeffs = sq ? vistrutith_mixcolumns_coeffs_sq : vistrutith_mixcolumns_coeffs;
  const bf512_t v1 = coeffs[0];
  const bf512_t v2 = coeffs[1];
  const bf512_t v3 = coeffs[2];

  for (size_t base = 0; base < nbytes; base += 16u) {
    bf512_t out_val_blk[16];
    bf512_t out_tag_blk[16];

    for (unsigned int c = 0; c < 4u; ++c) {
      const unsigned int i0 = 4u * c;
      const unsigned int i1 = i0 + 1u;
      const unsigned int i2 = i0 + 2u;
      const unsigned int i3 = i0 + 3u;

      const bf512_t a0v = in_val[base + i0];
      const bf512_t a1v = in_val[base + i1];
      const bf512_t a2v = in_val[base + i2];
      const bf512_t a3v = in_val[base + i3];
      const bf512_t a0t = in_tag[base + i0];
      const bf512_t a1t = in_tag[base + i1];
      const bf512_t a2t = in_tag[base + i2];
      const bf512_t a3t = in_tag[base + i3];

      out_val_blk[i0] = bf512_add(bf512_add(bf512_mul(a0v, v2), bf512_mul(a1v, v3)),
                                  bf512_add(bf512_mul(a2v, v1), bf512_mul(a3v, v1)));
      out_val_blk[i1] = bf512_add(bf512_add(bf512_mul(a0v, v1), bf512_mul(a1v, v2)),
                                  bf512_add(bf512_mul(a2v, v3), bf512_mul(a3v, v1)));
      out_val_blk[i2] = bf512_add(bf512_add(bf512_mul(a0v, v1), bf512_mul(a1v, v1)),
                                  bf512_add(bf512_mul(a2v, v2), bf512_mul(a3v, v3)));
      out_val_blk[i3] = bf512_add(bf512_add(bf512_mul(a0v, v3), bf512_mul(a1v, v1)),
                                  bf512_add(bf512_mul(a2v, v1), bf512_mul(a3v, v2)));

      out_tag_blk[i0] = bf512_add(bf512_add(bf512_mul(a0t, v2), bf512_mul(a1t, v3)),
                                  bf512_add(bf512_mul(a2t, v1), bf512_mul(a3t, v1)));
      out_tag_blk[i1] = bf512_add(bf512_add(bf512_mul(a0t, v1), bf512_mul(a1t, v2)),
                                  bf512_add(bf512_mul(a2t, v3), bf512_mul(a3t, v1)));
      out_tag_blk[i2] = bf512_add(bf512_add(bf512_mul(a0t, v1), bf512_mul(a1t, v1)),
                                  bf512_add(bf512_mul(a2t, v2), bf512_mul(a3t, v3)));
      out_tag_blk[i3] = bf512_add(bf512_add(bf512_mul(a0t, v3), bf512_mul(a1t, v1)),
                                  bf512_add(bf512_mul(a2t, v1), bf512_mul(a3t, v2)));
    }

    memcpy(out_val + base, out_val_blk, sizeof(out_val_blk));
    memcpy(out_tag + base, out_tag_blk, sizeof(out_tag_blk));
  }
}

void vistrutith_mixcolumns_verifier(bf512_t* out_key, const bf512_t* in_key,
                                    size_t nbytes, bool sq) {
  if ((nbytes & 15u) != 0u) {
    return;
  }
  const bf512_t* coeffs = sq ? vistrutith_mixcolumns_coeffs_sq : vistrutith_mixcolumns_coeffs;
  const bf512_t v2 = coeffs[1];

  /* clarify-261002-1000_xhs1.txt item 2: factor each coefficient's MixColumns map to four multiplications per column. */
  for (size_t base = 0; base < nbytes; base += 16u) {
    bf512_t out_key_blk[16];
    for (unsigned int c = 0; c < 4u; ++c) {
      const unsigned int i = 4u * c;
      const bf512_t* a = in_key + base + i;
      const bf512_t total = bf512_add(bf512_add(a[0], a[1]), bf512_add(a[2], a[3]));
      for (unsigned int r = 0; r < 4u; ++r) {
        out_key_blk[i + r] =
            bf512_add(bf512_add(total, a[r]), bf512_mul(v2, bf512_add(a[r], a[(r + 1u) & 3u])));
      }
    }
    memcpy(out_key + base, out_key_blk, sizeof(out_key_blk));
  }
}

static void vistrutith_gamma_all_u8(uint8_t x, uint8_t* g09, uint8_t* g0b, uint8_t* g0d,
                                    uint8_t* g0e) {
  const uint8_t x0 = get_bit(x, 0);
  const uint8_t x1 = get_bit(x, 1);
  const uint8_t x2 = get_bit(x, 2);
  const uint8_t x3 = get_bit(x, 3);
  const uint8_t x4 = get_bit(x, 4);
  const uint8_t x5 = get_bit(x, 5);
  const uint8_t x6 = get_bit(x, 6);
  const uint8_t x7 = get_bit(x, 7);

  *g09 = (uint8_t)(set_bit(x0 ^ x5, 0) ^ set_bit(x1 ^ x5 ^ x6, 1) ^ set_bit(x2 ^ x6 ^ x7, 2) ^
                   set_bit(x0 ^ x3 ^ x5 ^ x7, 3) ^ set_bit(x1 ^ x4 ^ x5 ^ x6, 4) ^
                   set_bit(x2 ^ x5 ^ x6 ^ x7, 5) ^ set_bit(x3 ^ x6 ^ x7, 6) ^
                   set_bit(x4 ^ x7, 7));
  *g0b = (uint8_t)(set_bit(x0 ^ x5 ^ x7, 0) ^ set_bit(x0 ^ x1 ^ x5 ^ x6 ^ x7, 1) ^
                   set_bit(x1 ^ x2 ^ x6 ^ x7, 2) ^ set_bit(x0 ^ x2 ^ x3 ^ x5, 3) ^
                   set_bit(x1 ^ x3 ^ x4 ^ x5 ^ x6 ^ x7, 4) ^
                   set_bit(x2 ^ x4 ^ x5 ^ x6 ^ x7, 5) ^ set_bit(x3 ^ x5 ^ x6 ^ x7, 6) ^
                   set_bit(x4 ^ x6 ^ x7, 7));
  *g0d = (uint8_t)(set_bit(x0 ^ x5 ^ x6, 0) ^ set_bit(x1 ^ x5 ^ x7, 1) ^
                   set_bit(x0 ^ x2 ^ x6, 2) ^ set_bit(x0 ^ x1 ^ x3 ^ x5 ^ x6 ^ x7, 3) ^
                   set_bit(x1 ^ x2 ^ x4 ^ x5 ^ x7, 4) ^ set_bit(x2 ^ x3 ^ x5 ^ x6, 5) ^
                   set_bit(x3 ^ x4 ^ x6 ^ x7, 6) ^ set_bit(x4 ^ x5 ^ x7, 7));
  *g0e = (uint8_t)(set_bit(x5 ^ x6 ^ x7, 0) ^ set_bit(x0 ^ x5, 1) ^ set_bit(x0 ^ x1 ^ x6, 2) ^
                   set_bit(x0 ^ x1 ^ x2 ^ x5 ^ x6, 3) ^ set_bit(x1 ^ x2 ^ x3 ^ x5, 4) ^
                   set_bit(x2 ^ x3 ^ x4 ^ x6, 5) ^ set_bit(x3 ^ x4 ^ x5 ^ x7, 6) ^
                   set_bit(x4 ^ x5 ^ x6, 7));
}

static void vistrutith_gamma_all_bits(const bf512_t x_bits[8], bf512_t g09_bits[8],
                                      bf512_t g0b_bits[8], bf512_t g0d_bits[8],
                                      bf512_t g0e_bits[8]) {
  g09_bits[0] = bf512_add(x_bits[0], x_bits[5]);
  g09_bits[1] = bf512_add(bf512_add(x_bits[1], x_bits[5]), x_bits[6]);
  g09_bits[2] = bf512_add(bf512_add(x_bits[2], x_bits[6]), x_bits[7]);
  g09_bits[3] = bf512_add(bf512_add(x_bits[0], x_bits[3]), bf512_add(x_bits[5], x_bits[7]));
  g09_bits[4] = bf512_add(bf512_add(x_bits[1], x_bits[4]), bf512_add(x_bits[5], x_bits[6]));
  g09_bits[5] = bf512_add(bf512_add(x_bits[2], x_bits[5]), bf512_add(x_bits[6], x_bits[7]));
  g09_bits[6] = bf512_add(bf512_add(x_bits[3], x_bits[6]), x_bits[7]);
  g09_bits[7] = bf512_add(x_bits[4], x_bits[7]);

  g0b_bits[0] = bf512_add(bf512_add(x_bits[0], x_bits[5]), x_bits[7]);
  g0b_bits[1] = bf512_add(bf512_add(x_bits[0], x_bits[1]),
                          bf512_add(bf512_add(x_bits[5], x_bits[6]), x_bits[7]));
  g0b_bits[2] = bf512_add(bf512_add(x_bits[1], x_bits[2]), bf512_add(x_bits[6], x_bits[7]));
  g0b_bits[3] = bf512_add(bf512_add(x_bits[0], x_bits[2]), bf512_add(x_bits[3], x_bits[5]));
  g0b_bits[4] = bf512_add(
      bf512_add(x_bits[1], x_bits[3]),
      bf512_add(bf512_add(x_bits[4], x_bits[5]), bf512_add(x_bits[6], x_bits[7])));
  g0b_bits[5] = bf512_add(bf512_add(x_bits[2], x_bits[4]),
                          bf512_add(bf512_add(x_bits[5], x_bits[6]), x_bits[7]));
  g0b_bits[6] = bf512_add(bf512_add(x_bits[3], x_bits[5]), bf512_add(x_bits[6], x_bits[7]));
  g0b_bits[7] = bf512_add(bf512_add(x_bits[4], x_bits[6]), x_bits[7]);

  g0d_bits[0] = bf512_add(bf512_add(x_bits[0], x_bits[5]), x_bits[6]);
  g0d_bits[1] = bf512_add(bf512_add(x_bits[1], x_bits[5]), x_bits[7]);
  g0d_bits[2] = bf512_add(bf512_add(x_bits[0], x_bits[2]), x_bits[6]);
  g0d_bits[3] = bf512_add(bf512_add(x_bits[0], x_bits[1]),
                          bf512_add(bf512_add(x_bits[3], x_bits[5]),
                                    bf512_add(x_bits[6], x_bits[7])));
  g0d_bits[4] = bf512_add(bf512_add(x_bits[1], x_bits[2]),
                          bf512_add(bf512_add(x_bits[4], x_bits[5]), x_bits[7]));
  g0d_bits[5] = bf512_add(bf512_add(x_bits[2], x_bits[3]), bf512_add(x_bits[5], x_bits[6]));
  g0d_bits[6] = bf512_add(bf512_add(x_bits[3], x_bits[4]), bf512_add(x_bits[6], x_bits[7]));
  g0d_bits[7] = bf512_add(bf512_add(x_bits[4], x_bits[5]), x_bits[7]);

  g0e_bits[0] = bf512_add(bf512_add(x_bits[5], x_bits[6]), x_bits[7]);
  g0e_bits[1] = bf512_add(x_bits[0], x_bits[5]);
  g0e_bits[2] = bf512_add(bf512_add(x_bits[0], x_bits[1]), x_bits[6]);
  g0e_bits[3] = bf512_add(bf512_add(x_bits[0], x_bits[1]),
                          bf512_add(x_bits[2], bf512_add(x_bits[5], x_bits[6])));
  g0e_bits[4] = bf512_add(bf512_add(x_bits[1], x_bits[2]), bf512_add(x_bits[3], x_bits[5]));
  g0e_bits[5] = bf512_add(bf512_add(x_bits[2], x_bits[3]), bf512_add(x_bits[4], x_bits[6]));
  g0e_bits[6] = bf512_add(bf512_add(x_bits[3], x_bits[4]), bf512_add(x_bits[5], x_bits[7]));
  g0e_bits[7] = bf512_add(bf512_add(x_bits[4], x_bits[5]), x_bits[6]);
}

void vistrutith_bit_inv_mixcolumns_prover(uint8_t out_bits[16], bf512_t out_tag[128],
                                          const uint8_t in_bits[16],
                                          const bf512_t in_tag[128]) {
  for (unsigned int c = 0; c < 4u; ++c) {
    const uint8_t* a = in_bits + 4u * c;
    const bf512_t* a_tag = in_tag + 32u * c;
    uint8_t g09[4], g0b[4], g0d[4], g0e[4];
    bf512_t g09_tag[32], g0b_tag[32], g0d_tag[32], g0e_tag[32];

    for (unsigned int r = 0; r < 4u; ++r) {
      vistrutith_gamma_all_u8(a[r], &g09[r], &g0b[r], &g0d[r], &g0e[r]);
      vistrutith_gamma_all_bits(a_tag + r * 8u, g09_tag + r * 8u, g0b_tag + r * 8u,
                                g0d_tag + r * 8u, g0e_tag + r * 8u);
    }

    out_bits[4u * c + 0u] = (uint8_t)(g0e[0] ^ g0b[1] ^ g0d[2] ^ g09[3]);
    out_bits[4u * c + 1u] = (uint8_t)(g09[0] ^ g0e[1] ^ g0b[2] ^ g0d[3]);
    out_bits[4u * c + 2u] = (uint8_t)(g0d[0] ^ g09[1] ^ g0e[2] ^ g0b[3]);
    out_bits[4u * c + 3u] = (uint8_t)(g0b[0] ^ g0d[1] ^ g09[2] ^ g0e[3]);

    for (unsigned int bit = 0; bit < 8u; ++bit) {
      out_tag[8u * (4u * c + 0u) + bit] =
          bf512_add(bf512_add(g0e_tag[0u * 8u + bit], g0b_tag[1u * 8u + bit]),
                    bf512_add(g0d_tag[2u * 8u + bit], g09_tag[3u * 8u + bit]));
      out_tag[8u * (4u * c + 1u) + bit] =
          bf512_add(bf512_add(g09_tag[0u * 8u + bit], g0e_tag[1u * 8u + bit]),
                    bf512_add(g0b_tag[2u * 8u + bit], g0d_tag[3u * 8u + bit]));
      out_tag[8u * (4u * c + 2u) + bit] =
          bf512_add(bf512_add(g0d_tag[0u * 8u + bit], g09_tag[1u * 8u + bit]),
                    bf512_add(g0e_tag[2u * 8u + bit], g0b_tag[3u * 8u + bit]));
      out_tag[8u * (4u * c + 3u) + bit] =
          bf512_add(bf512_add(g0b_tag[0u * 8u + bit], g0d_tag[1u * 8u + bit]),
                    bf512_add(g09_tag[2u * 8u + bit], g0e_tag[3u * 8u + bit]));
    }
  }
}

void vistrutith_bit_inv_mixcolumns_verifier(bf512_t out_key[128], const bf512_t in_key[128]) {
  for (unsigned int c = 0; c < 4u; ++c) {
    const bf512_t* a_key = in_key + 32u * c;
    bf512_t g09_key[32], g0b_key[32], g0d_key[32], g0e_key[32];

    for (unsigned int r = 0; r < 4u; ++r) {
      vistrutith_gamma_all_bits(a_key + r * 8u, g09_key + r * 8u, g0b_key + r * 8u,
                                g0d_key + r * 8u, g0e_key + r * 8u);
    }

    for (unsigned int bit = 0; bit < 8u; ++bit) {
      out_key[8u * (4u * c + 0u) + bit] =
          bf512_add(bf512_add(g0e_key[0u * 8u + bit], g0b_key[1u * 8u + bit]),
                    bf512_add(g0d_key[2u * 8u + bit], g09_key[3u * 8u + bit]));
      out_key[8u * (4u * c + 1u) + bit] =
          bf512_add(bf512_add(g09_key[0u * 8u + bit], g0e_key[1u * 8u + bit]),
                    bf512_add(g0b_key[2u * 8u + bit], g0d_key[3u * 8u + bit]));
      out_key[8u * (4u * c + 2u) + bit] =
          bf512_add(bf512_add(g0d_key[0u * 8u + bit], g09_key[1u * 8u + bit]),
                    bf512_add(g0e_key[2u * 8u + bit], g0b_key[3u * 8u + bit]));
      out_key[8u * (4u * c + 3u) + bit] =
          bf512_add(bf512_add(g0b_key[0u * 8u + bit], g0d_key[1u * 8u + bit]),
                    bf512_add(g09_key[2u * 8u + bit], g0e_key[3u * 8u + bit]));
    }
  }
}

void vistrutith_bit_inv_shiftrows_prover(uint8_t out_bits[16], bf512_t out_tag[128],
                                         const uint8_t in_bits[16],
                                         const bf512_t in_tag[128]) {
  for (unsigned int r = 0; r < 4u; ++r) {
    for (unsigned int c = 0; c < 4u; ++c) {
      const unsigned int dst = 4u * c + r;
      const unsigned int src = 4u * ((c + 4u - r) & 3u) + r;
      out_bits[dst] = in_bits[src];
      memcpy(out_tag + dst * 8u, in_tag + src * 8u, 8u * sizeof(*out_tag));
    }
  }
}

void vistrutith_bit_inv_shiftrows_verifier(bf512_t out_key[128], const bf512_t in_key[128]) {
  for (unsigned int r = 0; r < 4u; ++r) {
    for (unsigned int c = 0; c < 4u; ++c) {
      const unsigned int dst = 4u * c + r;
      const unsigned int src = 4u * ((c + 4u - r) & 3u) + r;
      memcpy(out_key + dst * 8u, in_key + src * 8u, 8u * sizeof(*out_key));
    }
  }
}

/* clarify-261002-1000_xhs1.txt item 2: inverse affine constants change values and evaluate as Delta on the verifier. */
void vistrutith_bit_inv_sbox_affine_prover(uint8_t out_bits[16], bf512_t out_tag[128],
                                           const uint8_t in_bits[16],
                                           const bf512_t in_tag[128]) {
  const uint8_t c = UINT8_C(0x05); /* c_j = 1 for j in {0,2} */

  for (unsigned int i = 0; i < 16u; ++i) {
    uint8_t y = 0;

    for (unsigned int j = 0; j < 8u; ++j) {
      const unsigned int j1 = (j + 7u) & 7u;
      const unsigned int j3 = (j + 5u) & 7u;
      const unsigned int j6 = (j + 2u) & 7u;
      const uint8_t y_bit = (uint8_t)(get_bit(in_bits[i], j1) ^ get_bit(in_bits[i], j3) ^
                                       get_bit(in_bits[i], j6) ^ get_bit(c, j));
      const bf512_t t =
          bf512_add(bf512_add(in_tag[i * 8u + j1], in_tag[i * 8u + j3]),
                    in_tag[i * 8u + j6]);
      y |= (uint8_t)set_bit(y_bit, j);
      out_tag[i * 8u + j] = t;
    }
    out_bits[i] = y;
  }
}

void vistrutith_bit_inv_sbox_affine_verifier(bf512_t out_key[128], const bf512_t in_key[128],
                                           bf512_t delta) {
  const uint8_t c = UINT8_C(0x05); /* c_j = 1 for j in {0,2} */

  for (unsigned int i = 0; i < 16u; ++i) {
    for (unsigned int j = 0; j < 8u; ++j) {
      const unsigned int j1 = (j + 7u) & 7u;
      const unsigned int j3 = (j + 5u) & 7u;
      const unsigned int j6 = (j + 2u) & 7u;
      out_key[i * 8u + j] =
          bf512_add(bf512_add(in_key[i * 8u + j1], in_key[i * 8u + j3]),
                    bf512_add(in_key[i * 8u + j6], bf512_mul_bit(delta, get_bit(c, j))));
    }
  }
}

void vistrutith_inv_mix_prover(
    uint8_t out_bits[VISTRUTAH_512_BLOCK_SIZE],
    bf512_t out_tag[VISTRUTAH_512_BLOCK_SIZE * 8u],
    const uint8_t in_bits[VISTRUTAH_512_BLOCK_SIZE],
    const bf512_t in_tag[VISTRUTAH_512_BLOCK_SIZE * 8u]) {
  static const uint8_t pi_mix[16] = {0, 1, 2, 3, 8, 9, 10, 11, 4, 5, 6, 7, 12, 13, 14, 15};

  for (unsigned int j = 0; j < 16u; ++j) {
    const unsigned int u = pi_mix[j];
    for (unsigned int b = 0; b < 4u; ++b) {
      const unsigned int src = 4u * j + b;
      const unsigned int dst = 16u * b + u;
      out_bits[dst] = in_bits[src];
      memcpy(out_tag + dst * 8u, in_tag + src * 8u, 8u * sizeof(*out_tag));
    }
  }
}

void vistrutith_inv_mix_verifier(
    bf512_t out_key[VISTRUTAH_512_BLOCK_SIZE * 8u],
    const bf512_t in_key[VISTRUTAH_512_BLOCK_SIZE * 8u]) {
  static const uint8_t pi_mix[16] = {0, 1, 2, 3, 8, 9, 10, 11, 4, 5, 6, 7, 12, 13, 14, 15};

  for (unsigned int j = 0; j < 16u; ++j) {
    const unsigned int u = pi_mix[j];
    for (unsigned int b = 0; b < 4u; ++b) {
      const unsigned int src = 4u * j + b;
      const unsigned int dst = 16u * b + u;
      memcpy(out_key + dst * 8u, in_key + src * 8u, 8u * sizeof(*out_key));
    }
  }
}

static uint8_t vistrutith_unpack_norm_nibble(
    const uint8_t norm_packed[VISTRUTAH_512_BLOCK_SIZE / 2u], unsigned int byte_idx) {
  const uint8_t v = norm_packed[byte_idx >> 1u];
  if ((byte_idx & 1u) != 0u) {
    return (uint8_t)((v >> 4) & 0x0Fu);
  }
  return (uint8_t)(v & 0x0Fu);
}

/* clarify-261002-1000_xhs1.txt item 2: multiply full commitments, including cross terms. */
static vistrutith_deg2_t vistrutith_mul_deg1(bf512_t a0, bf512_t a1,
                                           bf512_t b0, bf512_t b1) {
  vistrutith_deg2_t p;
  p.c[0] = bf512_mul(a0, b0);
  p.c[2] = bf512_mul(a1, b1);
  p.c[1] = bf512_add(bf512_mul(bf512_add(a0, a1), bf512_add(b0, b1)),
                       bf512_add(p.c[0], p.c[2]));
  return p;
}

static vistrutith_deg3_t vistrutith_mul_deg2_deg1(const vistrutith_deg2_t* a,
                                                bf512_t b0, bf512_t b1) {
  /* clarify-261002-1000_xhs1.txt item 2: reuse the low product to retain all four coefficients with five multiplications. */
  const vistrutith_deg2_t low = vistrutith_mul_deg1(a->c[0], a->c[1], b0, b1);
  vistrutith_deg3_t p;
  p.c[0] = low.c[0];
  p.c[1] = low.c[1];
  p.c[2] = bf512_add(low.c[2], bf512_mul(a->c[2], b0));
  p.c[3] = bf512_mul(a->c[2], b1);
  return p;
}

/* clarify-261002-1000_xhs1.txt item 2: embed the unchanged shuffled key once per complete constraint evaluation. */
typedef struct {
  bf512_t val[VISTRUTAH_512_BLOCK_SIZE], tag[VISTRUTAH_512_BLOCK_SIZE];
  bf512_t sq_val[VISTRUTAH_512_BLOCK_SIZE], sq_tag[VISTRUTAH_512_BLOCK_SIZE];
} vistrutith_fixed_key_prover_cache_t;

typedef struct {
  bf512_t lifted[VISTRUTAH_512_BLOCK_SIZE], sq_lifted[VISTRUTAH_512_BLOCK_SIZE];
} vistrutith_fixed_key_verifier_cache_t;

static void vistrutith_fixed_key_prover_cache_init(
    vistrutith_fixed_key_prover_cache_t* cache,
    const uint8_t bits[VISTRUTAH_512_BLOCK_SIZE],
    const bf512_t tag[VISTRUTAH_512_BLOCK_SIZE * 8u]) {
  for (unsigned int b = 0; b < 4u; ++b) {
    const unsigned int base = 16u * b;
    vistrutith_state_to_bytes_prover(cache->val + base, cache->tag + base,
                                    bits + base, tag + base * 8u);
  }
  for (unsigned int u = 0; u < VISTRUTAH_512_BLOCK_SIZE; ++u) {
    bf512_t sq_bits_tag[8];
    cache->sq_val[u] = bf512_byte_combine_bits_sq(bits[u]);
    bf512_sq_bit(sq_bits_tag, tag + u * 8u);
    cache->sq_tag[u] = bf512_byte_combine(sq_bits_tag);
  }
}

static void vistrutith_fixed_key_verifier_cache_init(
    vistrutith_fixed_key_verifier_cache_t* cache,
    const bf512_t key[VISTRUTAH_512_BLOCK_SIZE * 8u], bf512_t delta) {
  bf512_t key_bytes[VISTRUTAH_512_BLOCK_SIZE];
  for (unsigned int b = 0; b < 4u; ++b) {
    const unsigned int base = 16u * b;
    vistrutith_state_to_bytes_verifier(key_bytes + base, key + base * 8u);
  }
  for (unsigned int u = 0; u < VISTRUTAH_512_BLOCK_SIZE; ++u) {
    bf512_t sq_bits_key[8];
    bf512_sq_bit(sq_bits_key, key + u * 8u);
    /* Preserve the degree-1 SquareBits map, then cache its degree-2 Delta lift. */
    cache->lifted[u] = bf512_mul(delta, key_bytes[u]);
    cache->sq_lifted[u] = bf512_mul(delta, bf512_byte_combine(sq_bits_key));
  }
}

/* clarify-261002-1000_xhs1.txt item 2: compute concrete top-degree values in the AES byte subfield, including arbitrary norm nibbles. */
static uint8_t vistrutith_norm_value_byte(uint8_t norm) {
  /* beta4 = beta8^6 + beta8^4, hence byte basis (1, 0x50, 0xb0, 0x0c). */
  return (uint8_t)((norm & 1u) ^
                   ((uint8_t)-(int)((norm >> 1u) & 1u) & UINT8_C(0x50)) ^
                   ((uint8_t)-(int)((norm >> 2u) & 1u) & UINT8_C(0xb0)) ^
                   ((uint8_t)-(int)((norm >> 3u) & 1u) & UINT8_C(0x0c)));
}

static uint8_t vistrutith_value_xtime(uint8_t x) {
  return (uint8_t)((x << 1u) ^ ((uint8_t)-(int)(x >> 7u) & UINT8_C(0x1b)));
}

static void vistrutith_forward_value_layer(uint8_t out[16], const uint8_t in[16]) {
  uint8_t affine[16], shifted[16];
  for (unsigned int u = 0; u < 16u; ++u) {
    const uint8_t z = in[u];
    affine[u] = (uint8_t)(z ^ ((z << 1u) | (z >> 7u)) ^
                             ((z << 2u) | (z >> 6u)) ^
                             ((z << 3u) | (z >> 5u)) ^
                             ((z << 4u) | (z >> 4u)) ^ UINT8_C(0x63));
  }
  for (unsigned int r = 0; r < 4u; ++r) {
    for (unsigned int c = 0; c < 4u; ++c) {
      shifted[4u * c + r] = affine[4u * ((c + r) & 3u) + r];
    }
  }
  for (unsigned int c = 0; c < 4u; ++c) {
    const uint8_t* a = shifted + 4u * c;
    const uint8_t total = (uint8_t)(a[0] ^ a[1] ^ a[2] ^ a[3]);
    for (unsigned int r = 0; r < 4u; ++r) {
      out[4u * c + r] = (uint8_t)(total ^ a[r] ^ vistrutith_value_xtime((uint8_t)(a[r] ^ a[(r + 1u) & 3u])));
    }
  }
}

static void vistrutith_forward_by_norm_prover_cached(
    vistrutith_deg2_t out_a[VISTRUTAH_512_BLOCK_SIZE],
    vistrutith_deg2_t out_a_sq[VISTRUTAH_512_BLOCK_SIZE],
    vistrutith_deg3_t z_norm[VISTRUTAH_512_BLOCK_SIZE],
    const uint8_t in_state_bits[VISTRUTAH_512_BLOCK_SIZE],
    const bf512_t in_state_tag[VISTRUTAH_512_BLOCK_SIZE * 8u],
    const uint8_t norm_packed[VISTRUTAH_512_BLOCK_SIZE / 2u],
    const bf512_t norm_tag[VISTRUTAH_512_BLOCK_SIZE * 4u],
    const vistrutith_fixed_key_prover_cache_t* fixed_key) {
  for (unsigned int b = 0; b < 4u; ++b) {
    const unsigned int byte_base = 16u * b;
    const unsigned int bit_base = byte_base * 8u;
    bf512_t c_val[128], c_tag[128];
    bf512_t p_coeff[3][128];
    uint8_t product_value[16], forward_value[16];

    vistrutith_state_to_conjugates_prover(c_val, c_tag, in_state_bits + byte_base,
                                         in_state_tag + bit_base);
    for (unsigned int u = 0; u < 16u; ++u) {
      const unsigned int t = byte_base + u;
      bf512_t h_val[4], h_tag[4];
      const uint8_t norm = vistrutith_unpack_norm_nibble(norm_packed, t);
      vistrutith_invnorm_to_conjugates_prover(h_val, h_tag, norm, norm_tag + 4u * t);
      uint8_t x16 = in_state_bits[t];
      for (unsigned int j = 0; j < 4u; ++j) x16 = bits_sq(x16);
      product_value[u] = bf8_mul(x16, vistrutith_norm_value_byte(norm));
      uint8_t conjugate_value = product_value[u];
      for (unsigned int j = 0; j < 8u; ++j) {
        const unsigned int idx = u * 8u + ((j + 4u) & 7u);
        vistrutith_deg2_t p;
        /* clarify-261002-1000_xhs1.txt item 2: only the concrete a1*b1 is embedded from GF8; retain both random-tag products and their complete cross term. */
        p.c[0] = bf512_mul(c_tag[idx], h_tag[j & 3u]);
        p.c[2] = bf512_byte_combine_bits(conjugate_value);
        p.c[1] = bf512_add(
            bf512_mul(bf512_add(c_tag[idx], c_val[idx]),
                       bf512_add(h_tag[j & 3u], h_val[j & 3u])),
            bf512_add(p.c[0], p.c[2]));
        for (unsigned int k = 0; k < 3u; ++k) {
          p_coeff[k][u * 8u + j] = p.c[k];
        }
        conjugate_value = bits_sq(conjugate_value);
      }
      vistrutith_deg2_t p0;
      for (unsigned int k = 0; k < 3u; ++k) {
        p0.c[k] = p_coeff[k][u * 8u];
      }
      z_norm[t] = vistrutith_mul_deg2_deg1(&p0, c_tag[u * 8u + 1u], c_val[u * 8u + 1u]);
      /* lift the degree-1 x summand by X^2 before adding it to the cubic. */
      z_norm[t].c[2] = bf512_add(z_norm[t].c[2], c_tag[u * 8u]);
      z_norm[t].c[3] = bf512_add(z_norm[t].c[3], c_val[u * 8u]);
    }

    for (unsigned int k = 0; k < 2u; ++k) {
      bf512_t aff[16], aff_sq[16], sr[16], sr_sq[16], mc[16], mc_sq[16];
      const bf512_t constant_scale = bf512_zero();
      /* affine constants are at X^2 and the degree-1 key is lifted by X. */
      vistrutith_sbox_affine_verifier(aff, p_coeff[k], 16u, false, constant_scale);
      vistrutith_sbox_affine_verifier(aff_sq, p_coeff[k], 16u, true, constant_scale);
      vistrutith_shiftrows_verifier(sr, aff, 16u);
      vistrutith_shiftrows_verifier(sr_sq, aff_sq, 16u);
      vistrutith_mixcolumns_verifier(mc, sr, 16u, false);
      vistrutith_mixcolumns_verifier(mc_sq, sr_sq, 16u, true);
      for (unsigned int u = 0; u < 16u; ++u) {
        const unsigned int t = byte_base + u;
        out_a[t].c[k] = mc[u];
        out_a_sq[t].c[k] = mc_sq[u];
        if (k == 1u) {
          out_a[t].c[k] = bf512_add(out_a[t].c[k], fixed_key->tag[t]);
          out_a_sq[t].c[k] = bf512_add(out_a_sq[t].c[k], fixed_key->sq_tag[t]);
        }
      }
    }
    /* clarify-261002-1000_xhs1.txt item 2: top coefficients use the same affine/ShiftRows/MixColumns in GF8; the squared map is its Frobenius square. */
    vistrutith_forward_value_layer(forward_value, product_value);
    for (unsigned int u = 0; u < 16u; ++u) {
      const unsigned int t = byte_base + u;
      out_a[t].c[2] = bf512_add(bf512_byte_combine_bits(forward_value[u]), fixed_key->val[t]);
      out_a_sq[t].c[2] = bf512_add(bf512_byte_combine_bits_sq(forward_value[u]), fixed_key->sq_val[t]);
    }
  }
}

void vistrutith_forward_by_norm_prover(
    vistrutith_deg2_t out_a[VISTRUTAH_512_BLOCK_SIZE],
    vistrutith_deg2_t out_a_sq[VISTRUTAH_512_BLOCK_SIZE],
    vistrutith_deg3_t z_norm[VISTRUTAH_512_BLOCK_SIZE],
    const uint8_t in_state_bits[VISTRUTAH_512_BLOCK_SIZE],
    const bf512_t in_state_tag[VISTRUTAH_512_BLOCK_SIZE * 8u],
    const uint8_t norm_packed[VISTRUTAH_512_BLOCK_SIZE / 2u],
    const bf512_t norm_tag[VISTRUTAH_512_BLOCK_SIZE * 4u],
    const uint8_t fixed_key_bits[VISTRUTAH_512_BLOCK_SIZE],
    const bf512_t fixed_key_tag[VISTRUTAH_512_BLOCK_SIZE * 8u]) {
  vistrutith_fixed_key_prover_cache_t cache;
  vistrutith_fixed_key_prover_cache_init(&cache, fixed_key_bits, fixed_key_tag);
  vistrutith_forward_by_norm_prover_cached(out_a, out_a_sq, z_norm, in_state_bits,
                                           in_state_tag, norm_packed, norm_tag, &cache);
}

static void vistrutith_forward_by_norm_verifier_cached(
    bf512_t out_a_key[VISTRUTAH_512_BLOCK_SIZE], bf512_t out_a_sq_key[VISTRUTAH_512_BLOCK_SIZE],
    bf512_t z_norm_key[VISTRUTAH_512_BLOCK_SIZE],
    const bf512_t in_state_key[VISTRUTAH_512_BLOCK_SIZE * 8u],
    const bf512_t norm_key[VISTRUTAH_512_BLOCK_SIZE * 4u],
    const vistrutith_fixed_key_verifier_cache_t* fixed_key, bf512_t delta) {
  const bf512_t delta_sq = bf512_mul(delta, delta);
  for (unsigned int b = 0; b < 4u; ++b) {
    const unsigned int byte_base = 16u * b;
    const unsigned int bit_base = byte_base * 8u;
    bf512_t c_key[128], p_key[128];
    bf512_t aff[16], aff_sq[16], sr[16], sr_sq[16], mc[16], mc_sq[16];

    vistrutith_state_to_conjugates_verifier(c_key, in_state_key + bit_base);
    for (unsigned int u = 0; u < 16u; ++u) {
      const unsigned int t = byte_base + u;
      bf512_t h_key[4];
      vistrutith_invnorm_to_conjugates_verifier(h_key, norm_key + 4u * t);
      for (unsigned int j = 0; j < 8u; ++j) {
        p_key[u * 8u + j] =
            bf512_mul(c_key[u * 8u + ((j + 4u) & 7u)], h_key[j & 3u]);
      }
      /* evaluate the same X^2 lift used by the prover. */
      z_norm_key[t] = bf512_add(bf512_mul(p_key[u * 8u], c_key[u * 8u + 1u]),
                                  bf512_mul(delta_sq, c_key[u * 8u]));
    }
    vistrutith_sbox_affine_verifier(aff, p_key, 16u, false, delta_sq);
    vistrutith_sbox_affine_verifier(aff_sq, p_key, 16u, true, delta_sq);
    vistrutith_shiftrows_verifier(sr, aff, 16u);
    vistrutith_shiftrows_verifier(sr_sq, aff_sq, 16u);
    vistrutith_mixcolumns_verifier(mc, sr, 16u, false);
    vistrutith_mixcolumns_verifier(mc_sq, sr_sq, 16u, true);
    for (unsigned int u = 0; u < 16u; ++u) {
      const unsigned int t = byte_base + u;
      out_a_key[t] = bf512_add(mc[u], fixed_key->lifted[t]);
      out_a_sq_key[t] = bf512_add(mc_sq[u], fixed_key->sq_lifted[t]);
    }
  }
}

void vistrutith_forward_by_norm_verifier(
    bf512_t out_a_key[VISTRUTAH_512_BLOCK_SIZE], bf512_t out_a_sq_key[VISTRUTAH_512_BLOCK_SIZE],
    bf512_t z_norm_key[VISTRUTAH_512_BLOCK_SIZE],
    const bf512_t in_state_key[VISTRUTAH_512_BLOCK_SIZE * 8u],
    const bf512_t norm_key[VISTRUTAH_512_BLOCK_SIZE * 4u],
    const bf512_t fixed_key_key[VISTRUTAH_512_BLOCK_SIZE * 8u], bf512_t delta) {
  vistrutith_fixed_key_verifier_cache_t cache;
  vistrutith_fixed_key_verifier_cache_init(&cache, fixed_key_key, delta);
  vistrutith_forward_by_norm_verifier_cached(out_a_key, out_a_sq_key, z_norm_key,
                                             in_state_key, norm_key, &cache, delta);
}

void vistrutith_backward_zerornd_by_bits_prover(
    uint8_t out_bits[VISTRUTAH_512_BLOCK_SIZE], bf512_t out_tag[VISTRUTAH_512_BLOCK_SIZE * 8u],
    const uint8_t m_bits[VISTRUTAH_512_BLOCK_SIZE],
    const bf512_t m_tag[VISTRUTAH_512_BLOCK_SIZE * 8u],
    const uint8_t rk_bits[VISTRUTAH_512_BLOCK_SIZE],
    const bf512_t rk_tag[VISTRUTAH_512_BLOCK_SIZE * 8u], const uint8_t rc_bits[16]) {
  uint8_t u_bits[VISTRUTAH_512_BLOCK_SIZE];
  bf512_t u_tag[VISTRUTAH_512_BLOCK_SIZE * 8u];
  uint8_t v_bits[VISTRUTAH_512_BLOCK_SIZE];
  bf512_t v_tag[VISTRUTAH_512_BLOCK_SIZE * 8u];

  for (unsigned int i = 0; i < VISTRUTAH_512_BLOCK_SIZE; ++i) {
    u_bits[i] = (uint8_t)(m_bits[i] ^ rk_bits[i]);
  }
  for (unsigned int i = 0; i < VISTRUTAH_512_BLOCK_SIZE * 8u; ++i) {
    u_tag[i] = bf512_add(m_tag[i], rk_tag[i]);
  }

  /* Branch 0 additionally xors RC_{i-1}. */
  for (unsigned int i = 0; i < 16u; ++i) {
    u_bits[i] ^= rc_bits[i];
  }
  /* clarify-261002-1000_xhs1.txt item 2: RC changes the value, not its constant tag. */

  vistrutith_inv_mix_prover(v_bits, v_tag, u_bits, u_tag);

  for (unsigned int b = 0; b < 4u; ++b) {
    const unsigned int byte_base = 16u * b;
    const unsigned int bit_base = byte_base * 8u;
    uint8_t m1_bits[16];
    bf512_t m1_tag[128];
    uint8_t m2_bits[16];
    bf512_t m2_tag[128];
    uint8_t y_bits[16];
    bf512_t y_tag[128];

    vistrutith_bit_inv_mixcolumns_prover(m1_bits, m1_tag, v_bits + byte_base, v_tag + bit_base);
    vistrutith_bit_inv_shiftrows_prover(m2_bits, m2_tag, m1_bits, m1_tag);
    vistrutith_bit_inv_sbox_affine_prover(y_bits, y_tag, m2_bits, m2_tag);

    memcpy(out_bits + byte_base, y_bits, sizeof(y_bits));
    memcpy(out_tag + bit_base, y_tag, sizeof(y_tag));
  }
}

void vistrutith_backward_zerornd_by_bits_verifier(
    bf512_t out_key[VISTRUTAH_512_BLOCK_SIZE * 8u],
    const bf512_t m_key[VISTRUTAH_512_BLOCK_SIZE * 8u],
    const bf512_t rk_key[VISTRUTAH_512_BLOCK_SIZE * 8u], const uint8_t rc_bits[16],
    bf512_t delta) {
  bf512_t u_key[VISTRUTAH_512_BLOCK_SIZE * 8u];
  bf512_t v_key[VISTRUTAH_512_BLOCK_SIZE * 8u];

  for (unsigned int i = 0; i < VISTRUTAH_512_BLOCK_SIZE * 8u; ++i) {
    u_key[i] = bf512_add(m_key[i], rk_key[i]);
  }

  /* Branch 0 additionally xors RC_{i-1}. */
  for (unsigned int bit_i = 0; bit_i < 16u * 8u; ++bit_i) {
    /* clarify-261002-1000_xhs1.txt item 2: evaluate degree-1 round constants with Delta. */
    u_key[bit_i] = bf512_add(u_key[bit_i], bf512_mul_bit(delta, ptr_get_bit(rc_bits, bit_i)));
  }

  vistrutith_inv_mix_verifier(v_key, u_key);

  for (unsigned int b = 0; b < 4u; ++b) {
    const unsigned int bit_base = 16u * 8u * b;
    bf512_t m1_key[128];
    bf512_t m2_key[128];
    bf512_t y_key[128];

    vistrutith_bit_inv_mixcolumns_verifier(m1_key, v_key + bit_base);
    vistrutith_bit_inv_shiftrows_verifier(m2_key, m1_key);
    vistrutith_bit_inv_sbox_affine_verifier(y_key, m2_key, delta);

    memcpy(out_key + bit_base, y_key, sizeof(y_key));
  }
}

void vistrutith_backward_finalrnd_by_bits_prover(
    uint8_t out_bits[VISTRUTAH_512_BLOCK_SIZE], bf512_t out_tag[VISTRUTAH_512_BLOCK_SIZE * 8u],
    const uint8_t ct_bits[VISTRUTAH_512_BLOCK_SIZE],
    const bf512_t ct_tag[VISTRUTAH_512_BLOCK_SIZE * 8u],
    const uint8_t rk_bits[VISTRUTAH_512_BLOCK_SIZE],
    const bf512_t rk_tag[VISTRUTAH_512_BLOCK_SIZE * 8u]) {
  for (unsigned int b = 0; b < 4u; ++b) {
    const unsigned int byte_base = 16u * b;
    const unsigned int bit_base = byte_base * 8u;
    uint8_t u_bits[16];
    bf512_t u_tag[128];
    uint8_t u_sr_bits[16];
    bf512_t u_sr_tag[128];
    uint8_t y_bits[16];
    bf512_t y_tag[128];

    for (unsigned int i = 0; i < 16u; ++i) {
      u_bits[i] = (uint8_t)(ct_bits[byte_base + i] ^ rk_bits[byte_base + i]);
    }
    for (unsigned int i = 0; i < 16u * 8u; ++i) {
      u_tag[i] = bf512_add(ct_tag[bit_base + i], rk_tag[bit_base + i]);
    }

    vistrutith_bit_inv_shiftrows_prover(u_sr_bits, u_sr_tag, u_bits, u_tag);
    vistrutith_bit_inv_sbox_affine_prover(y_bits, y_tag, u_sr_bits, u_sr_tag);

    memcpy(out_bits + byte_base, y_bits, sizeof(y_bits));
    memcpy(out_tag + bit_base, y_tag, sizeof(y_tag));
  }
}

void vistrutith_backward_finalrnd_by_bits_verifier(
    bf512_t out_key[VISTRUTAH_512_BLOCK_SIZE * 8u],
    const bf512_t ct_key[VISTRUTAH_512_BLOCK_SIZE * 8u],
    const bf512_t rk_key[VISTRUTAH_512_BLOCK_SIZE * 8u], bf512_t delta) {
  for (unsigned int b = 0; b < 4u; ++b) {
    const unsigned int bit_base = 16u * 8u * b;
    bf512_t u_key[128];
    bf512_t u_sr_key[128];
    bf512_t y_key[128];

    for (unsigned int i = 0; i < 16u * 8u; ++i) {
      u_key[i] = bf512_add(ct_key[bit_base + i], rk_key[bit_base + i]);
    }

    vistrutith_bit_inv_shiftrows_verifier(u_sr_key, u_key);
    vistrutith_bit_inv_sbox_affine_verifier(y_key, u_sr_key, delta);
    memcpy(out_key + bit_base, y_key, sizeof(y_key));
  }
}

void vistrutith_append_cstrnts_by_bits_prover(
    vistrutith_deg3_t z0[VISTRUTAH_512_BLOCK_SIZE],
    vistrutith_deg3_t z1[VISTRUTAH_512_BLOCK_SIZE],
    const vistrutith_deg2_t x[VISTRUTAH_512_BLOCK_SIZE],
    const vistrutith_deg2_t x_sq[VISTRUTAH_512_BLOCK_SIZE],
    const uint8_t y_bits[VISTRUTAH_512_BLOCK_SIZE],
    const bf512_t y_tag[VISTRUTAH_512_BLOCK_SIZE * 8u]) {
  for (unsigned int t = 0; t < VISTRUTAH_512_BLOCK_SIZE; ++t) {
    const bf512_t y_val = bf512_byte_combine_bits(y_bits[t]);
    const bf512_t y0 = bf512_byte_combine(y_tag + t * 8u);
    bf512_t y_sq_bits_tag[8];
    bf512_sq_bit(y_sq_bits_tag, y_tag + t * 8u);
    const bf512_t y_sq_val = bf512_byte_combine_bits_sq(y_bits[t]);
    const bf512_t y_sq0 = bf512_byte_combine(y_sq_bits_tag);

    /* clarify-261002-1000_xhs1.txt item 2: preserve all coefficients of each IO constraint. */
    z0[t] = vistrutith_mul_deg2_deg1(x_sq + t, y0, y_val);
    z1[t] = vistrutith_mul_deg2_deg1(x + t, y_sq0, y_sq_val);
    /* x is lifted by X, while y is lifted by X^2, to add at degree 3. */
    for (unsigned int k = 0; k < 3u; ++k) {
      z0[t].c[k + 1u] = bf512_add(z0[t].c[k + 1u], x[t].c[k]);
    }
    z1[t].c[2] = bf512_add(z1[t].c[2], y0);
    z1[t].c[3] = bf512_add(z1[t].c[3], y_val);
  }
}

void vistrutith_append_cstrnts_by_bits_verifier(
    bf512_t z0_key[VISTRUTAH_512_BLOCK_SIZE], bf512_t z1_key[VISTRUTAH_512_BLOCK_SIZE],
    const bf512_t x_key[VISTRUTAH_512_BLOCK_SIZE],
    const bf512_t x_sq_key[VISTRUTAH_512_BLOCK_SIZE],
    const bf512_t y_key[VISTRUTAH_512_BLOCK_SIZE * 8u], bf512_t delta) {
  /* evaluate the prover's degree lifts with Delta and Delta^2. */
  const bf512_t delta_sq = bf512_mul(delta, delta);
  for (unsigned int t = 0; t < VISTRUTAH_512_BLOCK_SIZE; ++t) {
    const bf512_t y_hat_key = bf512_byte_combine(y_key + t * 8u);
    bf512_t y_sq_bits_key[8];
    bf512_sq_bit(y_sq_bits_key, y_key + t * 8u);
    const bf512_t y_hat_sq_key = bf512_byte_combine(y_sq_bits_key);

    z0_key[t] = bf512_add(bf512_mul(x_sq_key[t], y_hat_key), bf512_mul(delta, x_key[t]));
    z1_key[t] = bf512_add(bf512_mul(x_key[t], y_hat_sq_key), bf512_mul(delta_sq, y_hat_key));
  }
}

/* Large proof arrays belong to one heap workspace. */
typedef struct {
  uint8_t fixed_key_bits[VISTRUTAH_512_BLOCK_SIZE];
  bf512_t fixed_key_tag[VISTRUTAH_512_BLOCK_SIZE * 8u];
  uint8_t round_keys_bits[(VISTRUTITH_ENC_CSTRNTS_STEPS + 1u) * VISTRUTAH_512_BLOCK_SIZE];
  bf512_t round_keys_tag[(VISTRUTITH_ENC_CSTRNTS_STEPS + 1u) * VISTRUTAH_512_BLOCK_SIZE * 8u];
  uint8_t p_bits[VISTRUTAH_512_BLOCK_SIZE];
  bf512_t p_tag[VISTRUTAH_512_BLOCK_SIZE * 8u];
  vistrutith_deg2_t a[VISTRUTAH_512_BLOCK_SIZE], a_sq[VISTRUTAH_512_BLOCK_SIZE];
  vistrutith_deg3_t z_norm_round[VISTRUTAH_512_BLOCK_SIZE];
  vistrutith_fixed_key_prover_cache_t fixed_key_cache;
  uint8_t y_bits[VISTRUTAH_512_BLOCK_SIZE];
  bf512_t y_tag[VISTRUTAH_512_BLOCK_SIZE * 8u];
  vistrutith_deg3_t z0[VISTRUTAH_512_BLOCK_SIZE], z1[VISTRUTAH_512_BLOCK_SIZE];
} vistrutith_enc_prover_workspace_t;

void vistrutith_enc_constraints_prover(
    vistrutith_deg3_t z_norm[VISTRUTITH_ENC_CSTRNTS_NORM_LEN],
    vistrutith_deg3_t z_io0[VISTRUTITH_ENC_CSTRNTS_IO_LEN],
    vistrutith_deg3_t z_io1[VISTRUTITH_ENC_CSTRNTS_IO_LEN],
    const uint8_t in_bits[VISTRUTAH_512_BLOCK_SIZE],
    const bf512_t in_tag[VISTRUTAH_512_BLOCK_SIZE * 8u],
    const uint8_t out_bits[VISTRUTAH_512_BLOCK_SIZE],
    const bf512_t out_tag[VISTRUTAH_512_BLOCK_SIZE * 8u],
    const uint8_t w[VISTRUTAH_WITNESS_TOTAL_BYTES],
    const bf512_t w_tag[VISTRUTAH_WITNESS_TOTAL_BYTES * 8u]) {
  vistrutith_enc_prover_workspace_t* workspace = malloc(sizeof(*workspace));
  if (!workspace) {
    abort();
  }


  const unsigned int steps = VISTRUTITH_ENC_CSTRNTS_STEPS;
  unsigned int norm_off = 0u;
  unsigned int io_off = 0u;



  memcpy(workspace->fixed_key_bits, w, VISTRUTAH_WITNESS_KEY_BYTES);
  memcpy(workspace->fixed_key_tag, w_tag, VISTRUTAH_WITNESS_KEY_BYTES * 8u * sizeof(*w_tag));

  // :8
  vistrutith_shuffle_key_prover(workspace->fixed_key_bits, workspace->fixed_key_tag);
  vistrutith_fixed_key_prover_cache_init(&workspace->fixed_key_cache, workspace->fixed_key_bits, workspace->fixed_key_tag);

  {
    uint8_t* rk0_bits = workspace->round_keys_bits;
    bf512_t* rk0_tag = workspace->round_keys_tag;
    memcpy(rk0_bits + 0u, workspace->fixed_key_bits + 16u, 16u);
    memcpy(rk0_bits + 16u, workspace->fixed_key_bits + 0u, 16u);
    memcpy(rk0_bits + 32u, workspace->fixed_key_bits + 48u, 16u);
    memcpy(rk0_bits + 48u, workspace->fixed_key_bits + 32u, 16u);
    memcpy(rk0_tag + 0u * 128u, workspace->fixed_key_tag + 1u * 128u, 128u * sizeof(*rk0_tag));
    memcpy(rk0_tag + 1u * 128u, workspace->fixed_key_tag + 0u * 128u, 128u * sizeof(*rk0_tag));
    memcpy(rk0_tag + 2u * 128u, workspace->fixed_key_tag + 3u * 128u, 128u * sizeof(*rk0_tag));
    memcpy(rk0_tag + 3u * 128u, workspace->fixed_key_tag + 2u * 128u, 128u * sizeof(*rk0_tag));
  }

  // :9-14
  for (unsigned int j = 1u; j <= steps; ++j) {
    uint8_t* rk_bits = workspace->round_keys_bits + j * VISTRUTAH_512_BLOCK_SIZE;
    bf512_t* rk_tag = workspace->round_keys_tag + j * VISTRUTAH_512_BLOCK_SIZE * 8u;
    const uint8_t* prev_bits = workspace->round_keys_bits + (j - 1u) * VISTRUTAH_512_BLOCK_SIZE;
    const bf512_t* prev_tag = workspace->round_keys_tag + (j - 1u) * VISTRUTAH_512_BLOCK_SIZE * 8u;

    memcpy(rk_bits, prev_bits, VISTRUTAH_512_BLOCK_SIZE);
    memcpy(rk_tag, prev_tag, VISTRUTAH_512_BLOCK_SIZE * 8u * sizeof(*rk_tag));
    vistrutith_rotate_bytes_prover(rk_bits + 0u, rk_tag + 0u, 5, 16);
    vistrutith_rotate_bytes_prover(rk_bits + 16u, rk_tag + 16u * 8u, 10, 16);
    vistrutith_rotate_bytes_prover(rk_bits + 32u, rk_tag + 32u * 8u, 5, 16);
    vistrutith_rotate_bytes_prover(rk_bits + 48u, rk_tag + 48u * 8u, 10, 16);
  }

  // :17-19
  for (unsigned int i = 0; i < VISTRUTAH_512_BLOCK_SIZE; ++i) {
    workspace->p_bits[i] = (uint8_t)(in_bits[i] ^ workspace->round_keys_bits[i]);
  }
  for (unsigned int i = 0; i < VISTRUTAH_512_BLOCK_SIZE * 8u; ++i) {
    workspace->p_tag[i] = bf512_add(in_tag[i], workspace->round_keys_tag[i]);
  }

  // :21
  vistrutith_forward_by_norm_prover_cached(workspace->a, workspace->a_sq, workspace->z_norm_round, workspace->p_bits, workspace->p_tag, w + VISTRUTAH_WITNESS_KEY_BYTES,
                                    w_tag + VISTRUTAH_WITNESS_KEY_BYTES * 8u, &workspace->fixed_key_cache);

  // :22
  memcpy(z_norm + norm_off, workspace->z_norm_round, sizeof(workspace->z_norm_round));
  // norm_off means norm_offset, Ni offset
  norm_off += VISTRUTAH_512_BLOCK_SIZE;

  // :24
  for (unsigned int i = 1u; i < steps; ++i) {
    // Mi offset
    const size_t mi_off = (size_t)VISTRUTAH_WITNESS_KEY_BYTES +
                          (size_t)VISTRUTAH_WITNESS_PACKED_ROUND_BYTES +
                          (size_t)(i - 1u) *
                              ((size_t)VISTRUTAH_TRACE_ROUND_BYTES +
                               (size_t)VISTRUTAH_WITNESS_PACKED_ROUND_BYTES);
    const uint8_t* m_bits = w + mi_off;
    const bf512_t* m_tag = w_tag + mi_off * 8u;
    const uint8_t* n_packed = m_bits + VISTRUTAH_TRACE_ROUND_BYTES;
    const bf512_t* n_tag = m_tag + VISTRUTAH_TRACE_ROUND_BYTES * 8u;
    const uint8_t* rc = ROUND_CONSTANTS + 16u * (i - 1u);
    const uint8_t* round_key_bits = workspace->round_keys_bits + i * VISTRUTAH_512_BLOCK_SIZE;
    const bf512_t* round_key_tag = workspace->round_keys_tag + i * VISTRUTAH_512_BLOCK_SIZE * 8u;


    // :25
    vistrutith_backward_zerornd_by_bits_prover(workspace->y_bits, workspace->y_tag, m_bits, m_tag, round_key_bits,
                                               round_key_tag, rc);

    // :26
    vistrutith_append_cstrnts_by_bits_prover(workspace->z0, workspace->z1, workspace->a, workspace->a_sq, workspace->y_bits, workspace->y_tag);
    memcpy(z_io0 + io_off, workspace->z0, sizeof(workspace->z0));
    memcpy(z_io1 + io_off, workspace->z1, sizeof(workspace->z1));
    io_off += VISTRUTAH_512_BLOCK_SIZE;

    // :27
    vistrutith_forward_by_norm_prover_cached(workspace->a, workspace->a_sq, workspace->z_norm_round, m_bits, m_tag, n_packed, n_tag,
                                      &workspace->fixed_key_cache);
    memcpy(z_norm + norm_off, workspace->z_norm_round, sizeof(workspace->z_norm_round));
    norm_off += VISTRUTAH_512_BLOCK_SIZE;
  }

  {
    const uint8_t* round_key_bits = workspace->round_keys_bits + steps * VISTRUTAH_512_BLOCK_SIZE;
    const bf512_t* round_key_tag = workspace->round_keys_tag + steps * VISTRUTAH_512_BLOCK_SIZE * 8u;

    // :31
    vistrutith_backward_finalrnd_by_bits_prover(workspace->y_bits, workspace->y_tag, out_bits, out_tag, round_key_bits,
                                                round_key_tag);
    // :32                                            
    vistrutith_append_cstrnts_by_bits_prover(workspace->z0, workspace->z1, workspace->a, workspace->a_sq, workspace->y_bits, workspace->y_tag);
    memcpy(z_io0 + io_off, workspace->z0, sizeof(workspace->z0));
    memcpy(z_io1 + io_off, workspace->z1, sizeof(workspace->z1));
    io_off += VISTRUTAH_512_BLOCK_SIZE;
  }

  assert(norm_off == VISTRUTITH_ENC_CSTRNTS_NORM_LEN);
  assert(io_off == VISTRUTITH_ENC_CSTRNTS_IO_LEN);
  free(workspace);
}

/* Large proof arrays belong to one heap workspace. */
typedef struct {
  bf512_t fixed_key_key[VISTRUTAH_512_BLOCK_SIZE * 8u];
  bf512_t round_keys_key[(VISTRUTITH_ENC_CSTRNTS_STEPS + 1u) * VISTRUTAH_512_BLOCK_SIZE * 8u];
  bf512_t p_key[VISTRUTAH_512_BLOCK_SIZE * 8u];
  bf512_t a_key[VISTRUTAH_512_BLOCK_SIZE];
  bf512_t a_sq_key[VISTRUTAH_512_BLOCK_SIZE];
  bf512_t z_norm_round_key[VISTRUTAH_512_BLOCK_SIZE];
  vistrutith_fixed_key_verifier_cache_t fixed_key_cache;
  bf512_t y_key[VISTRUTAH_512_BLOCK_SIZE * 8u];
  bf512_t z0_key[VISTRUTAH_512_BLOCK_SIZE], z1_key[VISTRUTAH_512_BLOCK_SIZE];
} vistrutith_enc_verifier_workspace_t;

void vistrutith_enc_constraints_verifier(
    bf512_t z_norm_key[VISTRUTITH_ENC_CSTRNTS_NORM_LEN],
    bf512_t z_io0_key[VISTRUTITH_ENC_CSTRNTS_IO_LEN],
    bf512_t z_io1_key[VISTRUTITH_ENC_CSTRNTS_IO_LEN],
    const bf512_t in_key[VISTRUTAH_512_BLOCK_SIZE * 8u],
    const bf512_t out_key[VISTRUTAH_512_BLOCK_SIZE * 8u],
    const bf512_t w_key[VISTRUTAH_WITNESS_TOTAL_BYTES * 8u], bf512_t delta) {
  vistrutith_enc_verifier_workspace_t* workspace = malloc(sizeof(*workspace));
  if (!workspace) {
    abort();
  }

  const unsigned int steps = VISTRUTITH_ENC_CSTRNTS_STEPS;
  unsigned int norm_off = 0u;
  unsigned int io_off = 0u;



  memcpy(workspace->fixed_key_key, w_key, VISTRUTAH_WITNESS_KEY_BYTES * 8u * sizeof(*w_key));
  vistrutith_shuffle_key_verifier(workspace->fixed_key_key);
  vistrutith_fixed_key_verifier_cache_init(&workspace->fixed_key_cache, workspace->fixed_key_key, delta);

  {
    bf512_t* rk0_key = workspace->round_keys_key;
    memcpy(rk0_key + 0u * 128u, workspace->fixed_key_key + 1u * 128u, 128u * sizeof(*rk0_key));
    memcpy(rk0_key + 1u * 128u, workspace->fixed_key_key + 0u * 128u, 128u * sizeof(*rk0_key));
    memcpy(rk0_key + 2u * 128u, workspace->fixed_key_key + 3u * 128u, 128u * sizeof(*rk0_key));
    memcpy(rk0_key + 3u * 128u, workspace->fixed_key_key + 2u * 128u, 128u * sizeof(*rk0_key));
  }

  for (unsigned int j = 1u; j <= steps; ++j) {
    bf512_t* rk_key = workspace->round_keys_key + j * VISTRUTAH_512_BLOCK_SIZE * 8u;
    const bf512_t* prev_key = workspace->round_keys_key + (j - 1u) * VISTRUTAH_512_BLOCK_SIZE * 8u;
    memcpy(rk_key, prev_key, VISTRUTAH_512_BLOCK_SIZE * 8u * sizeof(*rk_key));
    vistrutith_rotate_bytes_verifier(rk_key + 0u, 5, 16);
    vistrutith_rotate_bytes_verifier(rk_key + 16u * 8u, 10, 16);
    vistrutith_rotate_bytes_verifier(rk_key + 32u * 8u, 5, 16);
    vistrutith_rotate_bytes_verifier(rk_key + 48u * 8u, 10, 16);
  }

  for (unsigned int i = 0; i < VISTRUTAH_512_BLOCK_SIZE * 8u; ++i) {
    workspace->p_key[i] = bf512_add(in_key[i], workspace->round_keys_key[i]);
  }

  vistrutith_forward_by_norm_verifier_cached(
      workspace->a_key, workspace->a_sq_key, workspace->z_norm_round_key, workspace->p_key, w_key + VISTRUTAH_WITNESS_KEY_BYTES * 8u,
      &workspace->fixed_key_cache, delta);
  memcpy(z_norm_key + norm_off, workspace->z_norm_round_key, sizeof(workspace->z_norm_round_key));
  norm_off += VISTRUTAH_512_BLOCK_SIZE;

  for (unsigned int i = 1u; i < steps; ++i) {
    const size_t mi_off = (size_t)VISTRUTAH_WITNESS_KEY_BYTES +
                          (size_t)VISTRUTAH_WITNESS_PACKED_ROUND_BYTES +
                          (size_t)(i - 1u) *
                              ((size_t)VISTRUTAH_TRACE_ROUND_BYTES +
                               (size_t)VISTRUTAH_WITNESS_PACKED_ROUND_BYTES);
    const bf512_t* m_key = w_key + mi_off * 8u;
    const bf512_t* n_key = m_key + VISTRUTAH_TRACE_ROUND_BYTES * 8u;
    const uint8_t* rc = ROUND_CONSTANTS + 16u * (i - 1u);
    const bf512_t* round_key_key = workspace->round_keys_key + i * VISTRUTAH_512_BLOCK_SIZE * 8u;


    vistrutith_backward_zerornd_by_bits_verifier(workspace->y_key, m_key, round_key_key, rc, delta);
    vistrutith_append_cstrnts_by_bits_verifier(workspace->z0_key, workspace->z1_key, workspace->a_key, workspace->a_sq_key, workspace->y_key, delta);
    memcpy(z_io0_key + io_off, workspace->z0_key, sizeof(workspace->z0_key));
    memcpy(z_io1_key + io_off, workspace->z1_key, sizeof(workspace->z1_key));
    io_off += VISTRUTAH_512_BLOCK_SIZE;

    vistrutith_forward_by_norm_verifier_cached(workspace->a_key, workspace->a_sq_key, workspace->z_norm_round_key, m_key, n_key,
                                        &workspace->fixed_key_cache, delta);
    memcpy(z_norm_key + norm_off, workspace->z_norm_round_key, sizeof(workspace->z_norm_round_key));
    norm_off += VISTRUTAH_512_BLOCK_SIZE;
  }

  {
    const bf512_t* round_key_key = workspace->round_keys_key + steps * VISTRUTAH_512_BLOCK_SIZE * 8u;

    vistrutith_backward_finalrnd_by_bits_verifier(workspace->y_key, out_key, round_key_key, delta);
    vistrutith_append_cstrnts_by_bits_verifier(workspace->z0_key, workspace->z1_key, workspace->a_key, workspace->a_sq_key, workspace->y_key, delta);
    memcpy(z_io0_key + io_off, workspace->z0_key, sizeof(workspace->z0_key));
    memcpy(z_io1_key + io_off, workspace->z1_key, sizeof(workspace->z1_key));
    io_off += VISTRUTAH_512_BLOCK_SIZE;
  }

  assert(norm_off == VISTRUTITH_ENC_CSTRNTS_NORM_LEN);
  assert(io_off == VISTRUTITH_ENC_CSTRNTS_IO_LEN);
  free(workspace);
}
