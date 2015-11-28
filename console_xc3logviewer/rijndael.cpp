/* LibTomCrypt, modular cryptographic library -- Tom St Denis
*
* LibTomCrypt is a library that provides various cryptographic
* algorithms in a highly modular and flexible manner.
*
* The library is free for all purposes without any express
* guarantee it works.
*
* Tom St Denis, tomstdenis@gmail.com, http://libtom.org
*/

/* AES implementation by Tom St Denis
*
* Derived from the Public Domain source code by

---
* rijndael-alg-fst.c
*
* @version 3.0 (December 2000)
*
* Optimised ANSI C code for the Rijndael cipher (now AES)
*
* @author Vincent Rijmen <vincent.rijmen@esat.kuleuven.ac.be>
* @author Antoon Bosselaers <antoon.bosselaers@esat.kuleuven.ac.be>
* @author Paulo Barreto <paulo.barreto@terra.com.br>
---
*/
/**
@file aes.c
Implementation of AES
*/
#include "stdafx.h"

#include "tomcrypt.h"

#include "rijndael.h"
#include "rijndael_tables.h"

static ulong32 setup_mix(ulong32 temp)
{
	return (Te4_3[byte(temp, 2)]) ^
		(Te4_2[byte(temp, 1)]) ^
		(Te4_1[byte(temp, 0)]) ^
		(Te4_0[byte(temp, 3)]);
}

/**
Initialize the AES (Rijndael) block cipher
@param key The symmetric key you wish to pass
@param keylen The key length in bytes
@param num_rounds The number of rounds desired (0 for default)
@param skey The key in as scheduled by this function.
@return CRYPT_OK if successful
*/
int rijndael_setup(const unsigned char *key, int keylen, int num_rounds, rijndael_key *rijndael)
{
	int i, j;
	unsigned long temp, *rk;
	unsigned long *rrk;

	LTC_ARGCHK(key != NULL);
	LTC_ARGCHK(rijndael != NULL);

	if (keylen != 16 && keylen != 24 && keylen != 32)
		return CRYPT_INVALID_KEYSIZE;

	if (num_rounds != 0 && num_rounds != (10 + ((keylen / 8) - 2) * 2))
		return CRYPT_INVALID_ROUNDS;

	rijndael->Nr = 10 + ((keylen / 8) - 2) * 2;

	/* setup the forward key */
	i = 0;
	rk = rijndael->eK;
	LOAD32H(rk[0], key);
	LOAD32H(rk[1], key + 4);
	LOAD32H(rk[2], key + 8);
	LOAD32H(rk[3], key + 12);
	if (keylen == 16)
	{
		j = 44;
		for (;;)
		{
			temp = rk[3];
			rk[4] = rk[0] ^ setup_mix(temp) ^ rcon[i];
			rk[5] = rk[1] ^ rk[4];
			rk[6] = rk[2] ^ rk[5];
			rk[7] = rk[3] ^ rk[6];

			if (++i == 10)
				break;

			rk += 4;
		}
	}
	else if (keylen == 24)
	{
		j = 52;
		LOAD32H(rk[4], key + 16);
		LOAD32H(rk[5], key + 20);
		for (;;)
		{
			temp = rijndael->eK[rk - rijndael->eK + 5];

			rk[6] = rk[0] ^ setup_mix(temp) ^ rcon[i];
			rk[7] = rk[1] ^ rk[6];
			rk[8] = rk[2] ^ rk[7];
			rk[9] = rk[3] ^ rk[8];

			if (++i == 8)
				break;

			rk[10] = rk[4] ^ rk[9];
			rk[11] = rk[5] ^ rk[10];
			rk += 6;
		}
	}
	else if (keylen == 32)
	{
		j = 60;
		LOAD32H(rk[4], key + 16);
		LOAD32H(rk[5], key + 20);
		LOAD32H(rk[6], key + 24);
		LOAD32H(rk[7], key + 28);
		for (;;)
		{
			temp = rijndael->eK[rk - rijndael->eK + 7];
			rk[8] = rk[0] ^ setup_mix(temp) ^ rcon[i];
			rk[9] = rk[1] ^ rk[8];
			rk[10] = rk[2] ^ rk[9];
			rk[11] = rk[3] ^ rk[10];
			if (++i == 7)
			{
				break;
			}
			temp = rk[11];
			rk[12] = rk[4] ^ setup_mix(RORc(temp, 8));
			rk[13] = rk[5] ^ rk[12];
			rk[14] = rk[6] ^ rk[13];
			rk[15] = rk[7] ^ rk[14];
			rk += 8;
		}
	}
	else
	{
		/* this can't happen */
		return CRYPT_ERROR;
	}

	/* setup the inverse key now */
	rk = rijndael->dK;
	rrk = rijndael->eK + j - 4;

	/* apply the inverse MixColumn transform to all round keys but the first and the last: */
	/* copy first */
	*rk++ = *rrk++;
	*rk++ = *rrk++;
	*rk++ = *rrk++;
	*rk = *rrk;
	rk -= 3; rrk -= 3;

	for (i = 1; i < rijndael->Nr; i++)
	{
		rrk -= 4;
		rk += 4;

		temp = rrk[0];
		rk[0] =
			Tks0[byte(temp, 3)] ^
			Tks1[byte(temp, 2)] ^
			Tks2[byte(temp, 1)] ^
			Tks3[byte(temp, 0)];
		temp = rrk[1];
		rk[1] =
			Tks0[byte(temp, 3)] ^
			Tks1[byte(temp, 2)] ^
			Tks2[byte(temp, 1)] ^
			Tks3[byte(temp, 0)];
		temp = rrk[2];
		rk[2] =
			Tks0[byte(temp, 3)] ^
			Tks1[byte(temp, 2)] ^
			Tks2[byte(temp, 1)] ^
			Tks3[byte(temp, 0)];
		temp = rrk[3];
		rk[3] =
			Tks0[byte(temp, 3)] ^
			Tks1[byte(temp, 2)] ^
			Tks2[byte(temp, 1)] ^
			Tks3[byte(temp, 0)];           
	}

	/* copy last */
	rrk -= 4;
	rk += 4;
	*rk++ = *rrk++;
	*rk++ = *rrk++;
	*rk++ = *rrk++;
	*rk = *rrk;

	return CRYPT_OK;
}

int rijndael_ecb_encrypt(const unsigned char *pt, unsigned char *ct, rijndael_key *rijndael)
{
	unsigned long s0, s1, s2, s3, t0, t1, t2, t3, *rk;
	int Nr, r;

	LTC_ARGCHK(pt != NULL);
	LTC_ARGCHK(ct != NULL);
	LTC_ARGCHK(rijndael != NULL);

	Nr = rijndael->Nr;
	rk = rijndael->eK;

	/*
	* map byte array block to cipher state
	* and add initial round key:
	*/
	LOAD32H(s0, pt); s0 ^= rk[0];
	LOAD32H(s1, pt + 4); s1 ^= rk[1];
	LOAD32H(s2, pt + 8); s2 ^= rk[2];
	LOAD32H(s3, pt + 12); s3 ^= rk[3];

	/*
	* Nr - 1 full rounds:
	*/
	r = Nr >> 1;
	for (;;) {
		t0 =
			Te0(byte(s0, 3)) ^
			Te1(byte(s1, 2)) ^
			Te2(byte(s2, 1)) ^
			Te3(byte(s3, 0)) ^
			rk[4];
		t1 =
			Te0(byte(s1, 3)) ^
			Te1(byte(s2, 2)) ^
			Te2(byte(s3, 1)) ^
			Te3(byte(s0, 0)) ^
			rk[5];
		t2 =
			Te0(byte(s2, 3)) ^
			Te1(byte(s3, 2)) ^
			Te2(byte(s0, 1)) ^
			Te3(byte(s1, 0)) ^
			rk[6];
		t3 =
			Te0(byte(s3, 3)) ^
			Te1(byte(s0, 2)) ^
			Te2(byte(s1, 1)) ^
			Te3(byte(s2, 0)) ^
			rk[7];

		rk += 8;

		if (--r == 0)
			break;

		s0 =
			Te0(byte(t0, 3)) ^
			Te1(byte(t1, 2)) ^
			Te2(byte(t2, 1)) ^
			Te3(byte(t3, 0)) ^
			rk[0];
		s1 =
			Te0(byte(t1, 3)) ^
			Te1(byte(t2, 2)) ^
			Te2(byte(t3, 1)) ^
			Te3(byte(t0, 0)) ^
			rk[1];
		s2 =
			Te0(byte(t2, 3)) ^
			Te1(byte(t3, 2)) ^
			Te2(byte(t0, 1)) ^
			Te3(byte(t1, 0)) ^
			rk[2];
		s3 =
			Te0(byte(t3, 3)) ^
			Te1(byte(t0, 2)) ^
			Te2(byte(t1, 1)) ^
			Te3(byte(t2, 0)) ^
			rk[3];
	}

	/*
	* apply last round and
	* map cipher state to byte array block:
	*/
	s0 =
		(Te4_3[byte(t0, 3)]) ^
		(Te4_2[byte(t1, 2)]) ^
		(Te4_1[byte(t2, 1)]) ^
		(Te4_0[byte(t3, 0)]) ^
		rk[0];
	STORE32H(s0, ct);
	s1 =
		(Te4_3[byte(t1, 3)]) ^
		(Te4_2[byte(t2, 2)]) ^
		(Te4_1[byte(t3, 1)]) ^
		(Te4_0[byte(t0, 0)]) ^
		rk[1];
	STORE32H(s1, ct + 4);
	s2 =
		(Te4_3[byte(t2, 3)]) ^
		(Te4_2[byte(t3, 2)]) ^
		(Te4_1[byte(t0, 1)]) ^
		(Te4_0[byte(t1, 0)]) ^
		rk[2];
	STORE32H(s2, ct + 8);
	s3 =
		(Te4_3[byte(t3, 3)]) ^
		(Te4_2[byte(t0, 2)]) ^
		(Te4_1[byte(t1, 1)]) ^
		(Te4_0[byte(t2, 0)]) ^
		rk[3];
	STORE32H(s3, ct + 12);

	return CRYPT_OK;
}

/**
Decrypts a block of text with AES
@param ct The input ciphertext (16 bytes)
@param pt The output plaintext (16 bytes)
@param skey The key as scheduled
@return CRYPT_OK if successful
*/
int rijndael_ecb_decrypt(const unsigned char *ct, unsigned char *pt, rijndael_key *rijndael)
{
	unsigned long s0, s1, s2, s3, t0, t1, t2, t3, *rk;
	int Nr, r;

	LTC_ARGCHK(pt != NULL);
	LTC_ARGCHK(ct != NULL);
	LTC_ARGCHK(rijndael != NULL);

	Nr = rijndael->Nr;
	rk = rijndael->dK;

	/*
	* map byte array block to cipher state
	* and add initial round key:
	*/
	LOAD32H(s0, ct); s0 ^= rk[0];
	LOAD32H(s1, ct + 4); s1 ^= rk[1];
	LOAD32H(s2, ct + 8); s2 ^= rk[2];
	LOAD32H(s3, ct + 12); s3 ^= rk[3];

	/*
	* Nr - 1 full rounds:
	*/
	r = Nr >> 1;
	for (;;)
	{
		t0 =
			Td0(byte(s0, 3)) ^
			Td1(byte(s3, 2)) ^
			Td2(byte(s2, 1)) ^
			Td3(byte(s1, 0)) ^
			rk[4];
		t1 =
			Td0(byte(s1, 3)) ^
			Td1(byte(s0, 2)) ^
			Td2(byte(s3, 1)) ^
			Td3(byte(s2, 0)) ^
			rk[5];
		t2 =
			Td0(byte(s2, 3)) ^
			Td1(byte(s1, 2)) ^
			Td2(byte(s0, 1)) ^
			Td3(byte(s3, 0)) ^
			rk[6];
		t3 =
			Td0(byte(s3, 3)) ^
			Td1(byte(s2, 2)) ^
			Td2(byte(s1, 1)) ^
			Td3(byte(s0, 0)) ^
			rk[7];

		rk += 8;

		if (--r == 0)
			break;

		s0 =
			Td0(byte(t0, 3)) ^
			Td1(byte(t3, 2)) ^
			Td2(byte(t2, 1)) ^
			Td3(byte(t1, 0)) ^
			rk[0];
		s1 =
			Td0(byte(t1, 3)) ^
			Td1(byte(t0, 2)) ^
			Td2(byte(t3, 1)) ^
			Td3(byte(t2, 0)) ^
			rk[1];
		s2 =
			Td0(byte(t2, 3)) ^
			Td1(byte(t1, 2)) ^
			Td2(byte(t0, 1)) ^
			Td3(byte(t3, 0)) ^
			rk[2];
		s3 =
			Td0(byte(t3, 3)) ^
			Td1(byte(t2, 2)) ^
			Td2(byte(t1, 1)) ^
			Td3(byte(t0, 0)) ^
			rk[3];
	}

	/*
	* apply last round and
	* map cipher state to byte array block:
	*/
	s0 =
		(Td4[byte(t0, 3)] & 0xff000000) ^
		(Td4[byte(t3, 2)] & 0x00ff0000) ^
		(Td4[byte(t2, 1)] & 0x0000ff00) ^
		(Td4[byte(t1, 0)] & 0x000000ff) ^
		rk[0];
	STORE32H(s0, pt);
	s1 =
		(Td4[byte(t1, 3)] & 0xff000000) ^
		(Td4[byte(t0, 2)] & 0x00ff0000) ^
		(Td4[byte(t3, 1)] & 0x0000ff00) ^
		(Td4[byte(t2, 0)] & 0x000000ff) ^
		rk[1];
	STORE32H(s1, pt + 4);
	s2 =
		(Td4[byte(t2, 3)] & 0xff000000) ^
		(Td4[byte(t1, 2)] & 0x00ff0000) ^
		(Td4[byte(t0, 1)] & 0x0000ff00) ^
		(Td4[byte(t3, 0)] & 0x000000ff) ^
		rk[2];
	STORE32H(s2, pt + 8);
	s3 =
		(Td4[byte(t3, 3)] & 0xff000000) ^
		(Td4[byte(t2, 2)] & 0x00ff0000) ^
		(Td4[byte(t1, 1)] & 0x0000ff00) ^
		(Td4[byte(t0, 0)] & 0x000000ff) ^
		rk[3];
	STORE32H(s3, pt + 12);

	return CRYPT_OK;
}

/**
Gets suitable key size
@param keysize [in/out] The length of the recommended key (in bytes).  This function will store the suitable size back in this variable.
@return CRYPT_OK if the input key size is acceptable.
*/
int rijndael_keysize(int *keysize)
{
	LTC_ARGCHK(keysize != NULL);

	if (*keysize < 16)
		return CRYPT_INVALID_KEYSIZE;

	if (*keysize < 24)
	{
		*keysize = 16;
		return CRYPT_OK;
	}
	else if (*keysize < 32)
	{
		*keysize = 24;
		return CRYPT_OK;
	}
	else
	{
		*keysize = 32;
		return CRYPT_OK;
	}
}