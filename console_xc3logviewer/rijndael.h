
struct rijndael_key
{
	unsigned long eK[60], dK[60];
	int Nr;
};

int rijndael_setup(const unsigned char *key, int keylen, int num_rounds, rijndael_key *rijndael);
int rijndael_ecb_encrypt(const unsigned char *pt, unsigned char *ct, rijndael_key *rijndael);
int rijndael_ecb_decrypt(const unsigned char *ct, unsigned char *pt, rijndael_key *rijndael);
int rijndael_keysize(int *keysize);