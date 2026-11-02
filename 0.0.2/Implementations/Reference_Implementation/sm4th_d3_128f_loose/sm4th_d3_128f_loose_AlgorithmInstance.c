/*
The software is provided by the Institute of Commercial Cryptography Standards
(ICCS), and is used for algorithm submissions in the Next-generation Commercial
Cryptographic Algorithms Program (NGCC).

ICCS doesn't represent or warrant that the operation of the software will be
uninterrupted or error-free in all cases. ICCS will take no responsibility for
the use of the software or the results thereof, if the software is used for any
other purposes.
*/

#include "sm4th_d3_128f_loose_AlgorithmInstance.h"
#include "drng.h"
#include "sm4th_d3_128f_loose.h"
#include <stdbool.h>

// DRNG_ctx for generating pseudorandom numbers within the SIG scheme
extern DRNG_ctx drng_algorithm;

// The following should be used to get pseudorandom numbers
// get_random_number(&drng_algorithm, random_number, random_number_len_bits);

#define ptr_get_bit(value, index) (((value)[(index) / 8] >> ((index) % 8)) & 1)

unsigned long long sig_get_pk_len_bytes(void)
{
	return SM4TH_D3_F_LOOSE_PUBLIC_KEY_SIZE;
}

unsigned long long sig_get_sk_len_bytes(void)
{
	return SM4TH_D3_F_LOOSE_PRIVATE_KEY_SIZE;
}

unsigned long long sig_get_sn_len_bytes(void)
{
	return SM4TH_D3_F_LOOSE_SIGNATURE_SIZE;
}

// pk_len 和pk长度 相等是输入保障的
// 这里输入*pk和*len的目的是因为*pk的长度无法访问
int sig_keygen(
	unsigned char *pk, unsigned long long *pk_len_bytes,
	unsigned char *sk, unsigned long long *sk_len_bytes)
{
	/* Reject missing output buffers before sampling any randomness. */
	if (!pk || !sk || !pk_len_bytes || !sk_len_bytes) {
		return -1;
	}
	if (*pk_len_bytes != sig_get_pk_len_bytes() ||
	    *sk_len_bytes != sig_get_sk_len_bytes()) {
		return -1;
	}

	bool done = false;
	uint8_t sk_key[128 / 8];
	uint8_t sk_input[128 / 8];

	while (!done) {
		/* Do not use key material when randomness generation fails. */
		if (get_random_number(&drng_algorithm, sk_key, 128) != 0) {
			return -1;
		}
		done = (ptr_get_bit(sk_key, 0) & ptr_get_bit(sk_key, 1)) == 0;
	}

	/* Do not use key material when randomness generation fails. */
	if (get_random_number(&drng_algorithm, sk_input, 128) != 0) {
		return -1;
	}
	
	return sm4th_d3_128f_loose_keygen(pk, sk, sk_key, sk_input);
}

int sig_sign(
	unsigned char *sk, unsigned long long sk_len_bytes,
	unsigned char *m, unsigned long long m_len_bytes,
	unsigned char *sn, unsigned long long *sn_len_bytes)
{
	/* Check full-width lengths before narrowing them to size_t. */
	if (!sk || !sn || !sn_len_bytes || sk_len_bytes != sig_get_sk_len_bytes() ||
	    (!m && m_len_bytes) || m_len_bytes > (UINT64_C(1) << 60) ||
	    m_len_bytes > SIZE_MAX || *sn_len_bytes > SIZE_MAX ||
	    *sn_len_bytes < sig_get_sn_len_bytes()) {
		return -1;
	}

	/* Sample 384 signing-randomness bits independently of the PRG width. */
	uint8_t rho[SIGN_RANDOMNESS_BYTES];
	if (get_random_number(&drng_algorithm, rho, SIGN_RANDOMNESS_BITS) != 0) {
		*sn_len_bytes = 0;
		return -1;
	}
	/* Copy lengths by value; unsigned long long need not alias size_t. */
	size_t signature_len = (size_t)*sn_len_bytes;
	const int ret = sm4th_d3_128f_loose_sign_with_randomness(
		sk, m, (size_t)m_len_bytes, rho, sizeof(rho), sn, &signature_len);
	*sn_len_bytes = signature_len;
	return ret;
}

int sig_verify(
	unsigned char *pk, unsigned long long pk_len_bytes,
	unsigned char *sn, unsigned long long sn_len_bytes,
	unsigned char *m, unsigned long long m_len_bytes)
{
	/* Reject invalid inputs before converting the external message length. */
	if (!pk || !sn || (!m && m_len_bytes) || m_len_bytes > (UINT64_C(1) << 60) ||
	    m_len_bytes > SIZE_MAX || pk_len_bytes != sig_get_pk_len_bytes() ||
	    sn_len_bytes != sig_get_sn_len_bytes()) {
		return -1;
	}
	return sm4th_d3_128f_loose_verify(pk, m, (size_t) m_len_bytes, sn, (size_t) sn_len_bytes);
}
