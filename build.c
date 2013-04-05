#include<string.h>
#include<stdio.h>
#include<stdlib.h>
#include"des.h"
#include"padlock.h"
#include"config.h"
#include<math.h>

#define AES_MODE	0x81
#define TDEA_MODE	0x82

#define R_128	0x87
#define R_64	0x1B

#define d_ERROR		0x00
#define d_SUCCESS	0x01

//unsigned char key[48 + 1] = "4CF15134A2850DD58A3D10BA80570D384CF15134A2850DD5";	//TWO KEY 
//unsigned char key[48 + 1] = "8aa83bf8cbda10620bc1bf19fbb6cd58bc313d4a371ca8b5";	//THREE KEY
unsigned char key[48 + 1] = "7EBBEA1BA4A399EF7EBBEA1BA4A399EF";
//unsigned char key[33] = "2b7e151628aed2a6abf7158809cf4f3c";
unsigned char input[16 + 1] = "0000000000000000";
//unsigned char input[33] = "6bc1bee22e409f96e93d7e117393172a";

static unsigned char achr2nib(char chr) { //convert hexadecimal character to nibble
	switch (chr) {
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
			return (unsigned char) (chr - '0');
		case 'A':
		case 'B':
		case 'C':
		case 'D':
		case 'E':
		case 'F':
			return (unsigned char) (chr - 'A' + 10);
		case 'a':
		case 'b':
		case 'c':
		case 'd':
		case 'e':
		case 'f':
			return (unsigned char) (chr - 'a' + 10);
		default:
			break;
	}
	return 0x10;                //KO
}

/**************************************************************
 * Convert hexa string to hexa bin
 * @param bin : the result of convert hexa string [OUTPUT]
 * @param hex : hexa string [INPUT]
 * @param len : length of hexa string [INPUT]
 * @return
 *  ret : length of hexa bin
 */
int ahex2bin(unsigned char * bin, const char *hex, int len) {
	int ret;                    //to be returned: number of characters processed
	unsigned char tmp;

	//if non-zero, len is the length of acceptor buffer bin
	if(!len) {                  //calcualte length if missing
		len = strlen(hex);
        //CHECK(len % 2 == 0, lblKO); //there should be 2 source characters for each output byte
        //len /= 2;
	}
	ret = 0;
	while(len--) {
		tmp = achr2nib(*hex++);  //get first nibble
		if(tmp >= 0x10)
			break;
		*bin = (unsigned char) (tmp << 4);

		tmp = achr2nib(*hex++);  //get second nibble
		if (!(tmp < 0x10)) return 0;

		*bin |= tmp;

		bin++;
		ret++;
	}
	return ret;
}

/************************************************************
* Convert string to unsigned long long int.
* Params :
* - sBuff : buffer array [INPUT]
* - len : length of buffer array [INPUT]
* return 
* - ullint as unsigned long long int [OUTPUT]
*
*/
unsigned long long int str2ullint(unsigned char *sBuff, int len) {
	unsigned long long int ullint = 0x0L;
	int i;

	for(i = 0; i < len; i++) {
		ullint |= sBuff[i];
		if(i<7)
			ullint <<= 8;
	}

	return ullint;
}

/*******************************************************************
* Convert unsigned long long int to string.
* Params :
* - in : varible unsigned long long int that wil be converted [INPUT]
* - oBuff : buffer array [OUTPUT]
* - len_byte : length of buffer array [INPUT]
* return 
* - len as length of buffer array
*
*/
int ullint2str(unsigned long long int in, unsigned char *oBuff, int len_byte) {
	int len, i;
	unsigned long long int tmp = 0x0L;
	
	len = len_byte;
	tmp = in;

	for(i = len - 1; i >= 0; i--) {
		oBuff[i] = tmp;
		if(i != 0) tmp >>= 8;
	}
	
	return len;
}

unsigned char gethexa(unsigned char *strhex) {
        int i;
        unsigned char arrbin[16][5]= {"0000", "0001", "0010", "0011", "0100", "0101", "0110", "0111", "1000",
        "1001", "1010", "1011", "1100", "1101", "1110", "1111"};
        unsigned char byte[16] = {0x0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};

        for(i = 0; i < 16; i++)
                if(strcmp(strhex, arrbin[i]) == 0) return byte[i];

        return 0x0;
}

int strbin2strhex(unsigned char *binstr, unsigned char *binhex) {
        int i, j=0, len;

        unsigned char bintmp[5];
        unsigned char hextmp;

        memset(bintmp, 0x0, sizeof(bintmp));

        for(i = 0; i < strlen(binstr); i+=8) {
                memcpy(bintmp, &binstr[i], 4);
                hextmp = gethexa(bintmp);
                hextmp <<= 4;

                memcpy(bintmp, &binstr[i+4], 4);
                hextmp |= gethexa(bintmp);

                binhex[j] = hextmp;
                len = ++j;
        }
	return len;
}

void encryptDES_ECB(unsigned char *Key, int lenKey, unsigned char *plain, unsigned char *cipher) {
	int ret;
	des3_context ctx;

	if(lenKey == 16) {
		ret = des3_set2key_enc(&ctx, Key);
		if(ret != 0) printf("Set Key Failed\n");
	} else if(lenKey == 24) {
		ret = des3_set3key_enc(&ctx, Key);
		if(ret != 0) printf("Set Key Failed");
	}

	ret = des3_crypt_ecb(&ctx, plain, cipher);
	if(ret != 0) printf("Crypt Failed\n");
}

int encrypt_3DES(unsigned char *p_key_str, int len_p_key_str, unsigned char *p_src_str, unsigned char *p_iv_str, int p_len_src_str, unsigned char *output, int *len_output) {
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

	return d_ERROR;
}

void generateSubKey(unsigned char *Key, unsigned char METHOD, unsigned long long int *K1, unsigned long long int *K2) {
	unsigned char iKey[128];
	unsigned char iStr[24];
	unsigned char cipher[256+1];
	unsigned char acipher[8];
	unsigned char K_1[64+1];
	unsigned char K_2[64+1];
	unsigned long long int ullint = 0x0;
	int ret, i, len, b;
	des3_context ctx;
	aes_context actx;
	unsigned char tmp = 0x0;
	long uL= 0x0;
	
	memset(iKey, 0x0, sizeof(iKey));
	memset(iStr, 0x0, sizeof(iStr));
	memset(cipher, 0x0, sizeof(cipher));
	memset(K_1, 0x0, sizeof(K_1));
	memset(K_2, 0x0, sizeof(K_2));

	len = ahex2bin(iKey, Key, strlen(Key)); //printf("len iKey %d\n", strlen(key));

#if 0
	ret = aes_setkey_enc( &actx, iKey, 128);
	if(ret != 0) {printf("AES SET KEY FAILED\n"); return;}

	ret = aes_crypt_ecb(&actx, AES_ENCRYPT, iStr, cipher);
	if(ret != 0) {printf("AES FAILED ENCRYPT\n"); return;}
#endif

	if(METHOD == TDEA_MODE) {
		b = 8;	// for the TDEA algorithm, the bit length of the block 64 bits or 8 bytes
		encryptDES_ECB(iKey, len, iStr, cipher);	// params iStr should've 0^8 = 0x00000000
	} 
	else if(METHOD == AES_MODE) {
		b = 16; // for the AES algorithm, the bit length of the block 128 bits or 16 bytes 

	}

	ullint = str2ullint(cipher, b);
	ullint <<= 1;

	if(cipher[0] & 0x80) {	/* if the leftmost cipher's bit is 1 */
		ullint ^= R_64;
		*K1 = ullint;		
	}
	else { /* the leftmost cipher's bit is 0 */
		*K1 = ullint;
	}
	ullint2str(ullint, K_1, b);
/*	printf("K1 ");
	for(i = 0; i < 8; i++) printf("%02x ", K_1[i]);
	printf("\n");*/

	if(K_1[0] & 0x80) {	/* if the leftmost K1's bit is 1 */
		*K2 = (*K1 << 1) ^ R_64;
	}
	else {	/* the leftmost K1's bit is 0*/
		*K2 = *K1 << 1;
	}

	ullint2str(*K2, K_2, b);
/*	printf("K2 ");
	for(i = 0; i < 8; i++) printf("%02x ", K_2[i]);
	printf("\n");*/
}

void DES3_CBCEnc(unsigned char *key, int lenkey, unsigned char *src, int lensrc, unsigned char *iv, unsigned char *K, unsigned char *output) {
        unsigned char buff[lensrc + 1];
        int i;
        unsigned char tmp[lensrc + 1];
	unsigned char  *ptmp;
        des3_context ctx;

        memset(tmp, 0x02, sizeof(tmp));

        if(lenkey == 16) des3_set2key_enc(&ctx, key);
        else if(lenkey == 24) des3_set3key_enc(&ctx, key);

	memcpy(tmp, src, lensrc);
	ptmp = tmp;

        while(lensrc > 0) { 
               if(lensrc == 8) {
                        printf("K XOR\n");
                        for(i = 0; i < 8; i++) {
                                ptmp[i] ^= K[i]; printf("%02X ", ptmp[i]);}
                }
                for(i = 0; i < 8; i++) {
                        output[i] = iv[i] ^ ptmp[i];
                }
		printf("OKE\n");
                des3_crypt_ecb(&ctx, output, output);
                memcpy(iv, output, 8);
                ptmp += 8;
                output +=8;
                lensrc -=8;
        }
	printf("\n");
}

void createSeqBytes(int len, unsigned char *out) {
        unsigned char buff[len + 1];
        buff[0] = '1';
        memset(&buff[1], 0x30, len-1);
        memcpy(out, buff, len +1);
}

void MACProcess(unsigned char *message, unsigned char METHODE, unsigned char *Key) {
	int len, n, ret, j, b, lenKey, lenOut, i, lensrc;
	float fn, Mlen;
	unsigned long long int K1, K2 = 0x0;
	unsigned long long int fm = 0x0;	// last block message
	unsigned long long int fxm = 0x0;	// last block message xor with subkey
	unsigned char binMsg[256];
	unsigned char binKey[128];
	unsigned char Mn[8 + 1];
	unsigned char iv[8 + 1];
	unsigned char output[64];// = {0x80,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0};
	unsigned char tmp[256];
	unsigned char K_1[8+1];
	unsigned char K_2[8+1];
	des3_context ctx;

	memset(output, 0x0, sizeof(output));
	memset(iv, 0x0, sizeof(iv));
	memset(binMsg, 0x0, sizeof(binMsg));
	memset(Mn, 0x0, sizeof(Mn));
	memset(tmp, 0x0, sizeof(tmp));

	lensrc = ahex2bin(binMsg, message, strlen(message));
	
	if(METHODE == TDEA_MODE) b = 64;	// for the TDEA algorithm, the bit length of the block 64 bits or 8 bytes
	else b = 128;	// for the AES algorithm, the bit length of the block 128 bits or 16 bytes

	generateSubKey(Key, METHODE, &K1, &K2);
	ullint2str(K1, K_1, 8);
	ullint2str(K2, K_2, 8);	

	Mlen = lensrc * 8;

	lenKey = ahex2bin(binKey, Key, strlen(Key));
#if 1
	if(((int)Mlen % b) == 0) {
		DES3_CBCEnc(binKey, lenKey, binMsg, lensrc, iv, K_1, output);
	} 
	else {
		fn = Mlen / b;
		fn = ceil(fn);
		n = (int) fn;
		printf("n = %d\n", n);
		j = n*b - Mlen - 1;
		createSeqBytes(j, tmp);
		len = strbin2strhex(tmp, output);
//		len = 12;
		printf("j %d, n %d, b %d, Mlen %f, fn %f, len %d\n", j, n, b, Mlen, fn, len);
		memcpy(&binMsg[lensrc], output, len);
		lensrc += len;
		memset(output, 0x0, sizeof(output));
		DES3_CBCEnc(binKey, lenKey, binMsg, lensrc, iv, K_2, output);
	}

#endif
	printf("K1 ");
	for(i = 0; i < 8; i++) printf("%02X ", K_1[i]);
	printf("\n");

	printf("K2 ");
	for(i = 0; i < 8; i++) printf("%02X ", K_2[i]);
	printf("\n");

	printf("binKey ");
	for(i = 0; i < lenKey; i++) printf("%02X ", binKey[i]);
	printf("\n");

	printf("binMsg ");
	for(i = 0; i < lensrc; i++) printf("%02X ", binMsg[i]);
	printf("\n");

	printf("Output ");
	for(i = 0; i < lensrc; i++) printf("%02X ", output[i]);
	printf("\n");
}

void test() {
	int i;
	unsigned char key[24+1] = {0x8A,0xA8,0x3B,0xF8,0xCB,0xDA,0x10,0x62,0x0B,0xC1,0xBF,0x19,0xFB,0xB6,0xCD,0x58,0xBC,0x31,0x3D,0x4A,0x37,0x1C,0xA8,0xB5};
	//unsigned char src[8+1] = {0x6B,0xC1,0xBE,0xE2,0x2E,0x40,0x9F,0x96};
	//unsigned char src[8+1] = {0xE9,0x3D,0x7E,0x11,0x73,0x93,0x17,0x2A};
	unsigned char src[8+1] = {0xAE,0x2D,0x8A,0x57,0x80,0x00,0x00,0x00};
	unsigned char iv[8+1] = {0xDA,0xED,0xE0,0x62,0xDF,0xD9,0xE4,0x0F};
	unsigned char K2[8+1] = {0x23,0x31,0xD3,0xA6,0x29,0xCC,0xA6,0xA5};

	unsigned char output[8+1];

//	memset(iv, 0x0, sizeof(iv));
	for(i = 0; i < 8; i++) src[i] ^= K2[i];

	for(i = 0; i < 8; i++) src[i] ^= iv[i];
	
	encryptDES_ECB(key, 24, src, output);
	for(i = 0; i < 8; i++) printf("%02X ", output[i]);;

}
int main() {
	unsigned long long int K1, K2;
//	unsigned char buffer[16 + 1] = "0000000000000000";
//	unsigned char buffer[16 + 1] = "6bc1bee22e409f96";
//	unsigned char buffer[40 + 1] = "6bc1bee22e409f96e93d7e117393172aae2d8a57";
	unsigned char buffer[52 + 1] = "3D01000000120000010203040506070809101112131415161718";
//	unsigned char buffer[64 + 1] = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51";

	MACProcess(buffer, TDEA_MODE, key);

	printf("\n");
}
