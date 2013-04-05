#include<string.h>
#include"des.h"
#include"padlock.h"
#include"config.h"
#include<stdio.h>

#define d_ERR		0x99
#define d_SUCCESS	0x00

//unsigned char master_key[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
unsigned char master_key[16] = {0x7E, 0xBB, 0xEA, 0x1B, 0xA4, 0xA3, 0x99, 0xEF, 0x7E, 0xBB, 0xEA, 0x1B, 0xA4, 0xA3, 0x99, 0xEF};
//unsigned char master_key[16] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
//B7 36 96 0A FA 41 EE D7 B7 36 96 0A FA 41 EE D7

//unsigned char master_key[16] = {0xB7, 0x36, 0x96, 0x0A, 0xFA, 0x41, 0xEE, 0xD7, 0xB7, 0x36, 0x96, 0x0A, 0xFA, 0x41, 0xEE, 0xD7};
unsigned char iv[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
//unsigned char iv[8] = {0xB2, 0x06, 0xE2, 0x3D, 0x30, 0x83, 0xEF, 0x51};

int
encrypt_3DES(unsigned char *p_key_str, int len_p_key_str, unsigned char *p_src_str, unsigned char *p_iv_str, int p_len_src_str, unsigned char *output, int *len_output)
{
	int ret, src_len;
	unsigned char src_str[100];
	unsigned char iv_str[100];
	unsigned char key_str[100];
	des3_context ctx;

	memset(src_str, 0x00, sizeof(src_str));
	memset(iv_str, 0x00, sizeof(iv_str));
	memset(key_str, 0x00, sizeof(key_str));

	/* Initiate seeds or initiate vector */
	memcpy(iv_str, p_iv_str, 8);					// -> initial seeds

	/* copy all bytes master key */
	memcpy(key_str, p_key_str, len_p_key_str);

	/* prepare source to decrypt */
	src_len = p_len_src_str;
	memcpy(src_str, p_src_str, src_len);

	if( len_p_key_str == 16 )				//means 2 keys
		des3_set2key_enc( &ctx, key_str );
	else if( len_p_key_str == 24 )			//means 3 keys
	des3_set3key_enc( &ctx, key_str );

	*len_output = src_len;
	ret = des3_crypt_cbc( &ctx, DES_ENCRYPT, src_len, iv_str, src_str, output );
	if( ret == 0 )
		return d_SUCCESS;

	return d_ERR;
}

int
decrypt_3DES (unsigned char *p_key_str, int len_p_key_str, unsigned char *p_src_str, unsigned char *p_iv_str, int p_len_src_str, unsigned char *output, int *len_output)
{
	int ret, src_len;
	unsigned char src_str[100];
	unsigned char iv_str[100];
	unsigned char key_str[100];
	des3_context ctx;


	memset(src_str, 0x00, sizeof(src_str));
	memset(iv_str, 0x00, sizeof(iv_str));
	memset(key_str, 0x00, sizeof(key_str));

/* Initiate seeds or initiate vector */
	memcpy(iv_str, p_iv_str, 8);			// -> initial seeds

/* copy all bytes master key */
	memcpy(key_str, p_key_str, len_p_key_str);

/* prepare source to decrypt */
	src_len = p_len_src_str;
	memcpy(src_str, p_src_str, src_len);

	if( len_p_key_str == 16 )
		des3_set2key_dec( &ctx, key_str );
	else if( len_p_key_str == 24 )
		des3_set3key_dec( &ctx, key_str );

	*len_output = src_len;

	ret = des3_crypt_cbc( &ctx, DES_DECRYPT, src_len, iv_str, src_str, output );
	if( ret == 0 )
		return d_SUCCESS;

	//usrInfo(infErrDecrypt3KDES);
	return d_ERR;
}

void main() {
//05 3F 41 DA 27 26 E4 29 94 33 1C C3 29 DD 6B DB
	//unsigned char src[16] = {0x05,0x3F,0x41,0xDA,0x27,0x26,0xE4,0x29,0x94,0x33,0x1C,0xC3,0x29,0xDD,0x6B,0xDB};
	unsigned char src[32] = {0x3D,0x01,0x00,0x00,0x00,0x12,0x00,0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x0,0x0,0x0,0x0,0x0,0x0};
//	unsigned char src[8] = {0xBD,0x00,0x00,0x00,0x00,0x12,0x00,0x00};
	
	unsigned char output[255];
	unsigned char output2[255];
	int l_src, l_output, i, ret;

	des3_context ctx;

	memset(output, 0x00, sizeof(output));
	memset(output2, 0x00, sizeof(output2));
	
	encrypt_3DES(master_key, 16, src, iv, 32, output, &l_output);
	/*des3_set2key_enc( &ctx, master_key);

	ret = des3_crypt_cbc( &ctx, DES_DECRYPT, 16, iv, src, output );
	if( ret != 0 )
		printf("FAIL %x\n", (unsigned int)ret);*/
	//printf("output %d\n", strlen(output));
	printf("\nsrc");
	for(i = 0; i < l_output; i++) {
		printf(" %02x", src[i]);
	}

	printf("\n\nencrypt");
	for(i = 0; i < l_output; i++) {
		printf(" %02x", output[i]);
	}

	decrypt_3DES(master_key, 16, output, iv, 32, output2, &l_output);
	printf("\n\ndecrypt");
	for(i = 0; i < l_output; i++) {
		printf(" %02x", output2[i]);
	}
	printf("\n\n");
}

