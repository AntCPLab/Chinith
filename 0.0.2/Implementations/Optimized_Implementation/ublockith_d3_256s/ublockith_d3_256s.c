/*
Part of the codes are adapted from the UBLOCKITH implementation at https://ublockith.info/,
which uses SPDX-License-Identifier: MIT.
*/

#include "ublockith_d3_256s.h"

#include "compat.h"
#include "sig_impl.h"
#include "params.h"
#include "owf.h"
#include "utils_ublock/ublock.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

// memory layout of the public key: OWF input || OWF output
#define PK_INPUT(pk) (pk)
#define PK_OUTPUT(pk) (&pk[32])

// memory layout of the private key: OWF input || OWF key
#define SK_INPUT(sk) (sk)
#define SK_KEY(sk) (&sk[32])
#define ptr_get_bit(value, index) (((value)[(index) / 8] >> ((index) % 8)) & 1)

int ublockith_d3_256s_keygen(uint8_t* pk, uint8_t* sk, const uint8_t* sk_key,
                             const uint8_t* sk_input) {
  /* Validate raw KeyGen buffers before reading or writing them. */
  if (!pk || !sk || !sk_key || !sk_input) {
    return -1;
  }
  /* Explicit-key generation uses the same secret-key restriction. */
  if ((ptr_get_bit(sk_key, 0) & ptr_get_bit(sk_key, 1)) != 0) {
    return 1;
  }

  memcpy(SK_KEY(sk), sk_key, 32);
  memcpy(SK_INPUT(sk), sk_input, 32);

  ublockith_d3_256s_owf(SK_KEY(sk), SK_INPUT(sk), PK_OUTPUT(pk));
  memcpy(PK_INPUT(pk), SK_INPUT(sk), 32);
  return 0;
}

int ublockith_d3_256s_unpack_private_key(ublockith_d3_256s_unpacked_private_key_t* unpacked_sk,
                                         const uint8_t* sk) {
  if (!unpacked_sk || !sk) {
    return -1;
  }
  /* Reject an imported secret outside the proved keyspace. */
  if ((ptr_get_bit(SK_KEY(sk), 0) & ptr_get_bit(SK_KEY(sk), 1)) != 0) {
    return 1;
  }

  memcpy(unpacked_sk->owf_input, SK_INPUT(sk), sizeof(unpacked_sk->owf_input));
  memcpy(unpacked_sk->owf_key, SK_KEY(sk), sizeof(unpacked_sk->owf_key));

  ublockith_d3_256s_owf(SK_KEY(sk), SK_INPUT(sk), unpacked_sk->owf_output);

  const params_t* params = ublockith_params_d3_256s();
  const unsigned int witness_bytes = params->ell / 8;
  unpacked_sk->witness = malloc(witness_bytes);
  /* Return safely when witness allocation fails in release builds. */
  if (!unpacked_sk->witness) {
    return -1;
  }
  ublock_extend_witness(params, unpacked_sk->witness, unpacked_sk->owf_key, unpacked_sk->owf_input);
  return 0;
}

int ublockith_d3_256s_validate_keypair(const uint8_t* pk, const uint8_t* sk) {
  if (!sk || !pk) {
    return -1;
  }

  if ((ptr_get_bit(SK_KEY(sk), 0) & ptr_get_bit(SK_KEY(sk), 1)) != 0) {
    return 1;
  }

  uint8_t pk_check[UBLOCKITH_D3_256S_PUBLIC_KEY_SIZE];
  ublockith_d3_256s_owf(SK_KEY(sk), SK_INPUT(sk), PK_OUTPUT(pk_check));
  memcpy(PK_INPUT(pk_check), SK_INPUT(sk), 32);
  return timingsafe_bcmp(pk_check, pk, sizeof(pk_check)) == 0 ? 0 : 2;
}

/* Reject messages above the specification limit before processing them. */
/* Explicit randomness must have the prescribed nonzero length. */
int ublockith_d3_256s_sign_with_randomness(const uint8_t* sk, const uint8_t* message,
                                           size_t message_len, const uint8_t* rho, size_t rho_len,
                                           uint8_t* signature, size_t* signature_len) {
  if (!sk || !signature || !signature_len || *signature_len < UBLOCKITH_D3_256S_SIGNATURE_SIZE ||
      (!rho || rho_len != SIGN_RANDOMNESS_BYTES) || (!message && message_len) || message_len > (UINT64_C(1) << 60)) {
    return -1;
  }

  /* Initialize cleanup state before validating an unpacked private key. */
  ublockith_d3_256s_unpacked_private_key_t unpacked_sk = {0};
  int ret = ublockith_d3_256s_unpack_private_key(&unpacked_sk, sk);
  if (ret) {
    ublockith_d3_256s_clear_unpacked_private_key(&unpacked_sk);
    return ret;
  }

  ret = ublockith_d3_256s_unpacked_sign_with_randomness(&unpacked_sk, message, message_len, rho,
                                                         rho_len, signature, signature_len);
  ublockith_d3_256s_clear_unpacked_private_key(&unpacked_sk);
  return ret;
}

int ublockith_d3_256s_unpacked_sign_with_randomness(
    const ublockith_d3_256s_unpacked_private_key_t* sk, const uint8_t* message,
    size_t message_len, const uint8_t* rho, size_t rho_len, uint8_t* signature,
    size_t* signature_len) {
  /* Split signing requires a witness and exact-length randomness. */
  if (!sk || !sk->witness || (!rho || rho_len != SIGN_RANDOMNESS_BYTES) || !signature || !signature_len || *signature_len < UBLOCKITH_D3_256S_SIGNATURE_SIZE ||
      (!message && message_len) || message_len > (UINT64_C(1) << 60)) {
    return -1;
  }
  /* Split signing must also reject forbidden imported secret bits. */
  if ((ptr_get_bit(sk->owf_key, 0) & ptr_get_bit(sk->owf_key, 1)) != 0) {
    return 1;
  }

  const params_t* params = ublockith_params_d3_256s();
  /* Propagate counter exhaustion through the public signing API. */
  const int sign_result = ublockith_sign(params, signature, message, message_len, sk->owf_key, sk->owf_input,
                 sk->owf_output, sk->witness, rho, rho_len);
  if (sign_result != 0) {
    *signature_len = 0;
    return sign_result;
  }
  *signature_len = UBLOCKITH_D3_256S_SIGNATURE_SIZE;
  return 0;
}

int ublockith_d3_256s_verify(const uint8_t* pk, const uint8_t* message, size_t message_len,
                             const uint8_t* signature, size_t signature_len) {
  if (!pk || !signature || signature_len != UBLOCKITH_D3_256S_SIGNATURE_SIZE ||
      (!message && message_len) || message_len > (UINT64_C(1) << 60)) {
    return -1;
  }

  const params_t* params = ublockith_params_d3_256s();
  return ublockith_verify(params, message, message_len, signature, PK_INPUT(pk), PK_OUTPUT(pk));
}

void ublockith_d3_256s_clear_private_key(uint8_t* key) {
  explicit_bzero(key, UBLOCKITH_D3_256S_PRIVATE_KEY_SIZE);
}

void ublockith_d3_256s_clear_unpacked_private_key(ublockith_d3_256s_unpacked_private_key_t* key) {
  if (!key) {
    return;
  }
  if (key->witness) {
    const params_t* params = ublockith_params_d3_256s();
    const unsigned int witness_bytes = params->ell / 8;
    explicit_bzero(key->witness, witness_bytes);
    free(key->witness);
    key->witness = NULL;
  }
  explicit_bzero(key, sizeof(*key));
}
