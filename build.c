#include<string.h>
#include<stdio.h>
#include<stdlib.h>
#include"des.h"
#include"aes.h"
#include"padlock.h"
#include"config.h"
#include<math.h>

#define AES_MODE	0x81
#define TDEA_MODE	0x82

#define R_128	0x87
#define R_64	0x1B

#define comment 1

#define AES_128		128
#define AES_196		196
#define AES_256		256

#define d_ERROR		0x00
#define d_SUCCESS	0x01

unsigned char key[48 + 1] = "4CF15134A2850DD58A3D10BA80570D384CF15134A2850DD5";	//TWO KEY 
//unsigned char key[48 + 1] = "8aa83bf8cbda10620bc1bf19fbb6cd58bc313d4a371ca8b5";	//THREE KEY
//unsigned char key[48 + 1] = "B736960AFA41EED7B736960AFA41EED7";
//unsigned char key[33] = "2b7e151628aed2a6abf7158809cf4f3c";
//unsigned char key[33] = "0aaf803dd2a6252d851b69b9e4f63801";
//unsigned char key[33] = "7ebbea1ba4a399ef7ebbea1ba4a399ef";		//CMAC INTEGRITY WRITE TDEA
//unsigned char key[33] = "b736960afa41eed7b736960afa41eed7";		//CMAC FULLY ENCIPHERED READ TDEA
//unsigned char key[33] = "0aaf803dd2a6252d851b69b9e4f63801";		//CMAC INTEGRITY WRITE AES

unsigned char input[16 + 1] = "0000000000000000";
//unsigned char input[33] = "6bc1bee22e409f96e93d7e117393172a";
unsigned char const_Rb[16] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87
};
unsigned char const_Rb2[8] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1B
};

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

void encryptAES_ECB(unsigned char *Key, int lenKey, unsigned char *plain, unsigned char *cipher) {
	int ret, keySize;
	aes_context ctx;

	keySize = lenKey * 8;
	ret = aes_setkey_enc( &ctx,  Key, keySize );
	if(ret != 0) printf("Set Key 128 Failed\n");
	ret = aes_crypt_ecb( &ctx, AES_ENCRYPT, plain, cipher);
}

void leftshift_onebit(unsigned char *input,unsigned char *output, int len){
	int i;
	unsigned char overflow = 0;

	for ( i=len; i>=0; i-- ) {
		output[i] = input[i] << 1;
		output[i] |= overflow;
		overflow = (input[i] & 0x80)?1:0;
	}
	
	return;
} 

void xor_byte(unsigned char *a, unsigned char *b, unsigned char *out, int len) {
    int i;
    for (i=0;i<=len; i++)
    {
          out[i] = a[i] ^ b[i];
    }
}

/***************************************************************
* Generate subkey K1 and K2 from Key with AES or TDEA method
* Key : key to be used as cipher
* K1  : subkey K1
* K2  : subkey K2
* METHOD : AES_MODE or TDEA_MODE
*
*/
void generateSubKey(unsigned char *Key, unsigned char METHOD, unsigned char *K1, unsigned char *K2) {
	unsigned char iKey[128];
	unsigned char iStr[24];
	unsigned char cipher[256+1];
	unsigned char acipher[8];
	unsigned char K_1[64+1];
	unsigned char K_2[64+1];
	unsigned long long int ullint = 0x0;
	unsigned char tmp2[16 + 1];
	int ret, i, len, b;
	unsigned char tmp = 0x0;
	long uL= 0x0;
	
	memset(iKey, 0x0, sizeof(iKey));
	memset(iStr, 0x0, sizeof(iStr));
	memset(cipher, 0x0, sizeof(cipher));
	memset(K_1, 0x0, sizeof(K_1));
	memset(K_2, 0x0, sizeof(K_2));
	memset(tmp2, 0x0, sizeof(tmp2));

	len = ahex2bin(iKey, Key, strlen(Key)); //printf("len iKey %d\n", strlen(key));

	printf("len %d\n", len);
	if(METHOD == TDEA_MODE) {
		b = 8;	// for the TDEA algorithm, the bit length of the block 64 bits or 8 bytes
		encryptDES_ECB(iKey, len, iStr, cipher);	// params iStr should've 0^8 = 0x00000000
	} 
	else if(METHOD == AES_MODE) {
		b = 16; // for the AES algorithm, the bit length of the block 128 bits or 16 bytes 
		encryptAES_ECB(iKey, len, iStr, cipher);
	}

/*	ullint = str2ullint(cipher, b);
	ullint <<= 1;*/

	if((cipher[0] & 0x80) == 0) {	/* if the leftmost cipher's bit is 1 */
		if(METHOD == TDEA_MODE) leftshift_onebit(cipher, K1, 7);
		else leftshift_onebit(cipher, K1, 15);

	}
	else { /* the leftmost cipher's bit is 0 */
		if(METHOD == TDEA_MODE) {
			leftshift_onebit(cipher, tmp2, 7);
			xor_byte(tmp2, const_Rb2, K1, 7);
		} else {
			leftshift_onebit(cipher, tmp2, 15);
			xor_byte(tmp2, const_Rb, K1, 7);
		}
	}

	memset(tmp2, 0x0, sizeof(tmp2));
	if( (K1[0] & 0x80) == 0) {	/* if the leftmost K1's bit is 1 */
		if(METHOD == TDEA_MODE) leftshift_onebit(K1, K2, 7);
		else leftshift_onebit(K1, K2, 15);

	}
	else {	/* the leftmost K1's bit is 0*/
		if(METHOD == TDEA_MODE) {
			leftshift_onebit(K1, tmp2, 7);
			xor_byte(tmp2, const_Rb2, K2, 7);
		} else {
			leftshift_onebit(K1, tmp2, 15);
			xor_byte(tmp2, const_Rb, K2, 15);
		}

	}
}

void AES_CIPHMAC(unsigned char *key, int lenkey, unsigned char *src, int lensrc, unsigned char *iv, unsigned char *K, unsigned char *output) {
	int ret, keySize, i;
	aes_context ctx;
	unsigned char *ptmp;
	unsigned char tmp[lensrc + 1];

	memset(tmp, 0x0, sizeof(tmp));
	memcpy(tmp, src, lensrc);
	ptmp = tmp;
	keySize = lenkey * 8;
	ret = aes_setkey_enc(&ctx, key, keySize);
	if(ret != 0) printf("Set Key %d Failed\n", keySize);

	while(lensrc > 0) {
		if(lensrc == 16) {
			for(i = 0; i < 16; i++) ptmp[i] ^= K[i];
		}
		for(i = 0; i < 16; i++) output[i] = ptmp[i] ^ iv[i];

		aes_crypt_ecb(&ctx, AES_ENCRYPT, output, output);
		memcpy(iv, output, 16);
		ptmp += 16;
		output += 16;
		lensrc -= 16;
	}
}

void DES3_CIPHMAC(unsigned char *key, int lenkey, unsigned char *src, int lensrc, unsigned char *iv, unsigned char *K, unsigned char *output) {
        unsigned char buff[lensrc + 1];
        int i;
        unsigned char tmp[lensrc + 1];
	unsigned char  *ptmp;
        des3_context ctx;

        memset(tmp, 0x0, sizeof(tmp));

        if(lenkey == 16) des3_set2key_enc(&ctx, key);
        else if(lenkey == 24) des3_set3key_enc(&ctx, key);

	memcpy(tmp, src, lensrc);
	ptmp = tmp;

        while(lensrc > 0) { 
               if(lensrc == 8) {
                        for(i = 0; i < 8; i++)
                                ptmp[i] ^= K[i]; 
                }	
               	for(i = 0; i < 8; i++)
               	        output[i] = iv[i] ^ ptmp[i];
                
                des3_crypt_ecb(&ctx, output, output);
                memcpy(iv, output, 8);
                ptmp += 8;
                output +=8;
                lensrc -=8;
        }

}

/*******************************************
* Craete secuence binary format as string
* len : length of binnary string
* out : format binary as string
* example : "1000"
*
*/
void createSeqBytes(int len, unsigned char *out) {
        unsigned char buff[len + 1];
        buff[0] = '1';
        memset(&buff[1], 0x30, len-1);
        memcpy(out, buff, len +1);
}
/*******************************************************
* This function is used to calculate MAC
* message : buffer to calculate 
* METHODE : AES_MODE or TDEA_MODE
* Key     : key to be used as cipher and generate subkeys
* prmIv   : initial vector
*
*/
void MACProcess(unsigned char *message, unsigned char METHODE, unsigned char *Key, unsigned char *prmIv) {
	int len, n, ret, j, b, lenKey, lenOut, i, lensrc;
	float fn, Mlen;
	unsigned long long int K1, K2 = 0x0;
	unsigned char binMsg[256];
	unsigned char binKey[128];
	unsigned char Mn[8 + 1];
	unsigned char output[64];
	unsigned char tmp[256];
	unsigned char K_1[16+1];
	unsigned char K_2[16+1];

	memset(output, 0x0, sizeof(output));
	memset(binMsg, 0x0, sizeof(binMsg));
	memset(Mn, 0x0, sizeof(Mn));
	memset(tmp, 0x0, sizeof(tmp));
	
	lensrc = ahex2bin(binMsg, message, strlen(message));
	printf("lensrc %d\n", lensrc);
	if(METHODE == TDEA_MODE) b = 64;	// for the TDEA algorithm, the bit length of the block 64 bits or 8 bytes
	else b = 128;	// for the AES algorithm, the bit length of the block 128 bits or 16 bytes

	generateSubKey(Key, METHODE, K_1, K_2);
	

	Mlen = lensrc * 8;

	lenKey = ahex2bin(binKey, Key, strlen(Key));
#if 1
	if( ( ((int)Mlen % b ) == 0) && Mlen > 0) {
		if(METHODE == TDEA_MODE)
			DES3_CIPHMAC(binKey, lenKey, binMsg, lensrc, prmIv, K_1, output);
		else AES_CIPHMAC(binKey, lenKey, binMsg, lensrc, prmIv, K_1, output); 
	} 
	else {
                if(Mlen == 0)
                    j = b;
                else {
			fn = Mlen / b;
			fn = ceil(fn);
			n = (int) fn;
			printf("n = %d\n", n);
			j = n*b - Mlen - 1;
		}              
		createSeqBytes(j, tmp);
                printf("j %d, tmp %s \n", j, tmp);
		len = strbin2strhex(tmp, output);
//		len = 12;
		printf("j %d, n %d, b %d, Mlen %f, fn %f, len %d\n", j, n, b, Mlen, fn, len);
		memcpy(&binMsg[lensrc], output, len);
		lensrc += len;
		memset(output, 0x0, sizeof(output));
		if(METHODE == TDEA_MODE) DES3_CIPHMAC(binKey, lenKey, binMsg, lensrc, prmIv, K_2, output);
		else AES_CIPHMAC(binKey, lenKey, binMsg, lensrc, prmIv, K_2, output);
	}

#endif
	if(METHODE == TDEA_MODE) len = 8;
	else len = 16;

#if 1
	printf("K1 ");
	for(i = 0; i < len; i++) printf("%02X ", K_1[i]);
	printf("\n");

	printf("K2 ");
	for(i = 0; i < len; i++) printf("%02X ", K_2[i]);
	printf("\n");

	printf("binKey ");
	for(i = 0; i < lenKey; i++) printf("%02X ", binKey[i]);
	printf("\n");

	printf("binMsg ");
	for(i = 0; i < lensrc; i++) printf("%02X ", binMsg[i]);
	printf("\n");

	printf("Output ");
	for(i = 0; i < lensrc; i++) printf("%02X ", output[i]);
#endif
	printf("\n");

}

int main() {
	unsigned long long int K1, K2;
	unsigned char iv[16 + 1];
//	unsigned char buffer[16 + 1] = "0000000000000000";
	unsigned char buffer[16 + 1] = "6bc1bee22e409f96";
//	unsigned char buffer[40 + 1] = "6bc1bee22e409f96e93d7e117393172a";
//	unsigned char buffer[40 + 1] = "6bc1bee22e409f96e93d7e117393172aae2d8a57";
//	unsigned char buffer[52 + 1] = "3D01000000120000010203040506070809101112131415161718";
//	unsigned char buffer[64 + 1] = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51";
//	unsigned char buffer[80 + 1] = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411";
//	unsigned char buffer[80 + 1] = "3d030000001500000102030405060708090a0b0c0d0e0f101112131415";
//	unsigned char buffer[80 + 1] = "3d01000000120000010203040506070809101112131415161718";	//WRITE CMAC TDEA
//	unsigned char buffer[80 + 1] = "";	//READ FULL ENCIPHERED TDEA
//	unsigned char buffer[80 + 1] = "bd01000000120000";	//READ INTEGRITY TDEA
//	unsigned char buffer[80 + 1] = "bd03000000150000";	//READ INTEGRITY AES
//	unsigned char buffer[80 + 1] = "3d030000001500000102030405060708090a0b0c0d0e0f101112131415";	//WRITE INTEGRITY AES
//	unsigned char buffer[128 + 1] = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710";
//	unsigned char buffer[52 + 1] = "BD00000000120000";
	memset(iv, 0x0, sizeof(iv));
//	 memcpy(iv, "\xAD\x37\x51\x6C\x10\x29\x64\x0E", 8);
//      	memcpy(iv, "\xB2\x06\xE2\x3D\x30\x83\xEF\x51", 8);
//      memcpy(iv, "\xA6\x58\x9D\xC8\xFC\x47\xD2\xE4\xF3\x7A\xF6\x45\xC3\xEB\xA0\x7D", 16);

	MACProcess(buffer, TDEA_MODE, key, iv);

	printf("\n");
}
