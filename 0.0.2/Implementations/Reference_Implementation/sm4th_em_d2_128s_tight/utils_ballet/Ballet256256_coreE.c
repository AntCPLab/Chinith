#include "Ballet256256_coreE.h"
#include <string.h>

/* Byte buffers and PRG output slices need not be uint64_t-aligned. */
static u64i ballet_load_word(const u8i *p)
{
	u64i value;
	memcpy(&value, p, sizeof(value));
	return value;
}

static void ballet_store_word(u8i *p, u64i value)
{
	memcpy(p, &value, sizeof(value));
}



void BalletGenRK_256_256_ENC(u8i * Rk, u8i * K)
{
	u64i i;
	u64i  k0, k1, k2, k3;
	u8i *p = Rk;
	k1 = ballet_load_word(K);
	k0 = ballet_load_word(K + 8);
	k3 = ballet_load_word(K + 16);
	k2 = ballet_load_word(K + 24);

	k0 = SWAP64(k0);
	k1 = SWAP64(k1);
	k2 = SWAP64(k2);
	k3 = SWAP64(k3);
	 
		for (i = 0; i < RoundBallet256256; i += 2)
		{
			ballet_store_word(p, k0);
			ballet_store_word(p + 8, k1);
			//   printf("%016I64x %016I64x\n", k00, k01 ); 
			k0 ^= ((k2 << 3) | (k3 >> 61)) ^ ((k2 << 5) | (k3 >> 59)) ^ i;
			k1 ^= ((k3 << 3) | (k2 >> 61)) ^ ((k3 << 5) | (k2 >> 59));
			ballet_store_word(p + 16, k2);
			ballet_store_word(p + 24, k3);
			//printf("%016I64x %016I64x\n", k10, k11 ); 
			k2 ^= ((k0 << 3) | (k1 >> 61)) ^ ((k0 << 5) | (k1 >> 59)) ^ (i + 1);
			k3 ^= ((k1 << 3) | (k0 >> 61)) ^ ((k1 << 5) | (k0 >> 59));
			p += 32;
		}

 
} 

void Ballet256256EncDataS(unsigned char *out, unsigned char *pt, unsigned char *rk)
{
	int i;
	u64i t0;
	u8i *trk = rk;
	u64i a = ballet_load_word(pt);
	u64i b = ballet_load_word(pt + 8);
	u64i c = ballet_load_word(pt + 16);
	u64i d = ballet_load_word(pt + 24);

	a = SWAP64(a); b = SWAP64(b);
	c = SWAP64(c); d = SWAP64(d);

	for (i = 0; i < RoundBallet256256; i += 2)
	{
		t0 = b ^ c;
		b ^= ballet_load_word(trk + 8);
		c ^= ballet_load_word(trk);
		b = ROTL64(b, 6);
		d = ROTL64(d, 15);
		a = ROTL64(a, 6);
		a += ROTL64(t0, 9);
		d += ROTL64(t0, 14);
		t0 = a ^ d;
		b += ROTL64(t0, 9);
		d ^= ballet_load_word(trk + 16);
		a ^= ballet_load_word(trk + 24);
		c = ROTL64(c, 15);
		c += ROTL64(t0, 14);
		trk += 32;

	}
	a = SWAP64(a); b = SWAP64(b);
	c = SWAP64(c); d = SWAP64(d);
	ballet_store_word(out, b);
	ballet_store_word(out + 8, a);
	ballet_store_word(out + 16, d);
	ballet_store_word(out + 24, c);
}
