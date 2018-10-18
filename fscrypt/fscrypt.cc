#include <stdio.h>
#include <cstring>

#include <iostream>
#include <string>

using namespace std;

#include "fscrypt.h"

/*
	Both functions allocate the result buffer of at least the required
	size (using new()) and return a pointer to it. Both functions 
	also return the number of valid bytes in the result buffer in resultlen.
	The application code is responsible for deleting the buffer.

	Use CBC mode of encryption. For padding, pad with length of the pad
	in all the padded characters.

	--

	Assume that the initialization vector contains NULL characters 
	(all 0's).

	Description of blowfish functions can be found at:
	https://www.openssl.org/docs/man1.0.2/crypto/blowfish.html
*/

void print_buf(string name, unsigned char* buf, int size) {

	cout << name << ": " << size << " bytes" << endl;
	for(int i=0; i<size; i++) {		
		if(i % BLOCKSIZE == 0 && i != 0) printf("\n");
		printf("%02x ", buf[i]);
	}
	printf("\n");
}

void* fs_encrypt(void* plaintext, int bufsize, char* keystr, int* resultlen) {
	printf("fs_encrypt()\n");
	print_buf("plaintext", (unsigned char*) plaintext, bufsize);
	print_buf("key", (unsigned char*) keystr, 16);

	// sets up the Blowfish key
	BF_KEY key;
	BF_set_key(&key, 16, (unsigned char*) keystr); // void BF_set_key(BF_KEY *key, int len, const unsigned char *data);	

	// create Initialization Vector (IV) containing NULL characters
	unsigned char* iv = new unsigned char[BLOCKSIZE]; // allocates 8 bytes
	memset(iv, 0, BLOCKSIZE); // initialize to NULL

	// allocate memory for result
	int pad_n = bufsize % BLOCKSIZE; // plaintext must be a multiple of 8 bytes
	printf("pad_n %i\n", pad_n);
	unsigned char* result = new unsigned char[bufsize + pad_n];
	memset(result, pad_n, bufsize + pad_n); // fill result buffer entirely with padding ; plaintext will overwrite the inital bytes
	memcpy(result, plaintext, bufsize);

	print_buf("to encrypt", result, bufsize + pad_n);

	// BF_cbc_encrypt(const unsigned char *in, unsigned char *out, long length, BF_KEY *schedule, unsigned char *ivec, int enc);	
	BF_cbc_encrypt(result, result, bufsize + pad_n, &key, iv, BF_ENCRYPT);

	print_buf("encrypted", result, bufsize + pad_n);
	*resultlen = bufsize + pad_n;
	
	return result;
}

void* fs_decrypt(void* ciphertext, int bufsize, char* keystr, int* resultlen) {
	printf("fs_decrypt()\n");
	print_buf("ciphertext", (unsigned char*) ciphertext, bufsize);
	print_buf("key", (unsigned char*) keystr, 16);

	// sets up the Blowfish key
	BF_KEY key;
	BF_set_key(&key, 16, (unsigned char*) keystr); // void BF_set_key(BF_KEY *key, int len, const unsigned char *data);	

	// create Initialization Vector (IV) containing NULL characters
	unsigned char* iv = new unsigned char[BLOCKSIZE]; // allocates 8 bytes
	memset(iv, 0, BLOCKSIZE); // initialize to NULL

	// copy over ciphertext ; will be directly modified here to decrypt 
	unsigned char* result = new unsigned char[bufsize];
	memcpy(result, ciphertext, bufsize);

	print_buf("to decrypt", result, bufsize);

	// BF_cbc_encrypt(const unsigned char *in, unsigned char *out, long length, BF_KEY *schedule, unsigned char *ivec, int enc);	
	BF_cbc_encrypt(result, result, bufsize, &key, iv, BF_DECRYPT);

	// remove padding
	int pad_n = result[bufsize - 1]; // the last byte should give us how many padding bytes were used
	char true_pad = 1;
	for(int i=bufsize-1; i>bufsize-pad_n; i--) {
		if(result[i] != pad_n) {
			true_pad = 0;	
			break;
		}
	}

	if(true_pad) *resultlen = bufsize - pad_n;
	else *resultlen = bufsize;
 
	print_buf("decrypted", result, *resultlen);

	return result;
}
