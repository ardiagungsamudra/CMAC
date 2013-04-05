#include<stdio.h>
#include"aes.h"
#include"padlock.h"
#include"config.h"
#include<string.h>

#define d_ERROR		0x99
#define d_SUCCESS	0x00

unsigned char master_key[16] = {0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA};

int encrypt_aes(unsigned char *masterkey, unsigned int lenKey, unsigned char *src, unsigned int lensrc, unsigned char *iv, unsigned char *output) {
	int len_key, ret;
	aes_context ctx;

	len_key = lenKey;

	ret = aes_setkey_enc( &ctx, masterkey, len_key * 8 );
	if(ret != 0) return d_ERROR;

	ret = aes_crypt_cbc(&ctx, AES_ENCRYPT, len_key, iv, src, output);
	if(ret != 0) return d_ERROR;

	//memcpy(iv, output, 16);

	return d_SUCCESS;
}

int decrypt_aes(unsigned char *masterkey, unsigned int lenKey, unsigned char *src, unsigned int lensrc, unsigned char *iv, unsigned char *output) {
	int len_key, ret;
	aes_context ctx;

	len_key = lenKey;

	ret = aes_setkey_dec( &ctx, masterkey, len_key * 8 );
	if(ret != 0) return d_ERROR;

	ret = aes_crypt_cbc(&ctx, AES_DECRYPT, len_key, iv, src, output);
	if(ret != 0) return d_ERROR;

	return d_SUCCESS;
}

int main () {
	unsigned char src[16] = {0x05,0x3F,0x41,0xDA,0x27,0x26,0xE4,0x29,0x94,0x33,0x1C,0xC3,0x29,0xDD,0x6B,0xDB};
	unsigned char iv[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	unsigned char iv2[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	unsigned char output[255];
	unsigned char output2[255];
	int l_src, l_output, i, ret;
	
	memset(output, 0x0, sizeof(output));
	memset(output2, 0x0, sizeof(output2));

	
	printf("src :");
	for(i = 0; i < 16; i++) {
		printf(" %02x", (unsigned int) src[i]);
	}

	printf("\n\niv :");
	for(i = 0; i < 16; i++) {
		printf(" %02x", (unsigned int) iv[i]);
	}

	ret = encrypt_aes(master_key, 16, src, 16, iv, output);	if(ret != d_SUCCESS) return 1;
	printf("\n\nencrypt :");
	for(i = 0; i < 16; i++) {
		printf(" %02x", (unsigned int) output[i]);
	}

	ret = decrypt_aes(master_key, 16, output, 16, iv2, output2);	if(ret != d_SUCCESS) return 1;
	printf("\n\ndecrypt :");
	for(i = 0; i < 16; i++) {
		printf(" %02x", (unsigned int) output2[i]);
	}

	printf("\n\niv2 :");
	for(i = 0; i < 16; i++) {
		printf(" %02x", (unsigned int) iv[i]);
	}

	printf("\n\n");
	return 1;
}
