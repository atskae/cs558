#include <stdio.h>
#include <cstdlib>
#include <cstring>
#include <math.h>

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

void print_char(string name, unsigned char* buf) {
	cout << name << ": ";
	for(int i=0; i<BLOCKSIZE; i++) {
		printf("%02x ", (unsigned char) *(buf+i));
	}
	printf("\n");
}

void print_buf(string name, unsigned char* buf, int size) {

	cout << name << ": " << size << " bytes" << endl;
	for(int i=0; i<size; i++) {		
		if(i % BLOCKSIZE == 0 && i != 0) printf("\n");
		printf("%02x ", (unsigned char) buf[i]);
	}
	printf("\n");
}

void print_buf_matrix(string name, unsigned char** buf, int block_n) {

	cout << name << endl;
	for(int i=0; i<block_n; i++) {
		printf("block %i: ", i);
		for(int j=0; j<BLOCKSIZE; j++) {	
			printf("%02x ", (unsigned char) buf[i][j]);
		}
		printf("\n");
	}
	//printf("\n");
}

int get_key_length(char* keystr) {
	int k = 0;
	while(keystr[k]) {
		k++;
	}
	return k;
}

void* fs_encrypt(void* plaintext, int bufsize, char* keystr, int* resultlen) {

	printf("fs_encrypt()\n");
	print_buf("plaintext", (unsigned char*) plaintext, bufsize);
	int k = get_key_length(keystr);
	print_buf("key", (unsigned char*) keystr, k);

	// sets up the Blowfish key
	BF_KEY key;
	BF_set_key(&key, k, (unsigned char*) keystr); // void BF_set_key(BF_KEY *key, int len, const unsigned char *data);	

	// create Initialization Vector (IV) containing NULL characters
	unsigned char* iv = new unsigned char[BLOCKSIZE];
	memset(iv, 0, BLOCKSIZE);

	// allocate memory for result
	int pad_n = (floor(bufsize/BLOCKSIZE)+1)*BLOCKSIZE - bufsize; // plaintext must be a multiple of 8 bytes
	int block_n = (bufsize + pad_n)/BLOCKSIZE;
	//printf("pad_n %i\n", pad_n);
	unsigned char** blocks = new unsigned char*[block_n];
	for(int i=0; i<block_n; i++) {
		blocks[i] = new unsigned char[BLOCKSIZE];
		for(int j=0; j<BLOCKSIZE; j++) {		
			if(BLOCKSIZE*i + j > bufsize) break;
			memcpy(blocks[i]+j, (unsigned char*) plaintext + BLOCKSIZE*i + j, 1);
		}
	}
	for(int i=0; i<pad_n; i++) {
		blocks[block_n-1][(BLOCKSIZE-1)-i] = pad_n;
	}	
	// print_buf_matrix("to encrypt", blocks, block_n);

	// encrypt in CBC mode using ebc	
	// void BF_ecb_encrypt(const unsigned char *in, unsigned char *out, BF_KEY *key, int enc);
	*blocks[0] ^= *iv; // XOR first plaintext block with the Initialization Vector
	BF_ecb_encrypt(blocks[0], blocks[0], &key, BF_ENCRYPT);

	for(int i=1; i<block_n; i++) {	
		//print_char("i-1", blocks[i-1]);
		//print_char("i", blocks[i]);
		*blocks[i] ^= *blocks[i-1];
		BF_ecb_encrypt(blocks[i], blocks[i], &key, BF_ENCRYPT);
	}
	print_buf_matrix("encrypted", blocks, block_n);

	// convert blocks to char*
	unsigned char* result = new unsigned char[block_n * BLOCKSIZE];	
	for(int i=0; i<block_n; i++) {
		memcpy(result + i*BLOCKSIZE, blocks[i], BLOCKSIZE);
	}

	// free blocks
	for(int i=0; i<block_n; i++) {
		delete[] blocks[i];
	}

	delete[] blocks;
	delete[] iv;
	
	// print_buf("CHAR STREAM", result, block_n * BLOCKSIZE);

	//// test decryption
	//for(int i=block_n-1; i>0; i--) {
	//	BF_ecb_encrypt(blocks[i], blocks[i], &key, BF_DECRYPT);
	//	*blocks[i] ^= *blocks[i-1];	
	//}
	//BF_ecb_encrypt(blocks[0], blocks[0], &key, BF_DECRYPT);
	//*blocks[0] ^= *iv;		
	//print_buf_matrix("decrypted", blocks, block_n);

	*resultlen = block_n * BLOCKSIZE;	
	return result;
}

void* fs_encrypt_correct(void* plaintext, int bufsize, char* keystr, int* resultlen) {
	printf("fs_encrypt_correct()\n");
	print_buf("plaintext", (unsigned char*) plaintext, bufsize);
	int k = get_key_length(keystr);
	print_buf("key", (unsigned char*) keystr, k);

	// sets up the Blowfish key
	BF_KEY key;
	BF_set_key(&key, k, (unsigned char*) keystr); // void BF_set_key(BF_KEY *key, int len, const unsigned char *data);	

	// create Initialization Vector (IV) containing NULL characters
	unsigned char* iv = new unsigned char[BLOCKSIZE]; // allocates 8 bytes
	memset(iv, 0, BLOCKSIZE); // initialize to NULL

	// allocate memory for result
	int pad_n = (floor(bufsize/BLOCKSIZE)+1)*BLOCKSIZE - bufsize; // plaintext must be a multiple of 8 bytes
	//printf("pad_n %i\n", pad_n);
	unsigned char* result = new unsigned char[bufsize + pad_n];
	memset(result, pad_n, bufsize + pad_n); // fill result buffer entirely with padding ; plaintext will overwrite the inital bytes
	memcpy(result, plaintext, bufsize);

	print_buf("to encrypt", result, bufsize + pad_n);

	// BF_cbc_encrypt(const unsigned char *in, unsigned char *out, long length, BF_KEY *schedule, unsigned char *ivec, int enc);	
	BF_cbc_encrypt(result, result, bufsize + pad_n, &key, iv, BF_ENCRYPT);

	delete[] iv;

	print_buf("encrypted", result, bufsize + pad_n);
	*resultlen = bufsize + pad_n;	
	return result;
}

void* fs_decrypt(void* ciphertext, int bufsize, char* keystr, int* resultlen) {

	printf("fs_decrypt()\n");
	print_buf("ciphertext", (unsigned char*) ciphertext, bufsize);
	int k = get_key_length(keystr);
	print_buf("key", (unsigned char*) keystr, k);

	// sets up the Blowfish key
	BF_KEY key;
	BF_set_key(&key, k, (unsigned char*) keystr); // void BF_set_key(BF_KEY *key, int len, const unsigned char *data);	

	// create Initialization Vector (IV) containing NULL characters
	unsigned char* iv = new unsigned char[BLOCKSIZE];
	memset(iv, 0, BLOCKSIZE);

	// allocate memory for result
	int block_n = (bufsize)/BLOCKSIZE;
	unsigned char** blocks = new unsigned char*[block_n];
	for(int i=0; i<block_n; i++) {
		blocks[i] = new unsigned char[BLOCKSIZE];
		for(int j=0; j<BLOCKSIZE; j++) {		
			memcpy(blocks[i], (unsigned char*) ciphertext + BLOCKSIZE*i, BLOCKSIZE);
		}
	}
	
	//print_buf_matrix("to decrypt", blocks, block_n);

	// decrypt in CBC mode using ebc	
	// void BF_ecb_encrypt(const unsigned char *in, unsigned char *out, BF_KEY *key, int enc);
	for(int i=block_n-1; i>0; i--) {	
		//print_char("i-1", blocks[i-1]);
		//print_char("i", blocks[i]);	
		BF_ecb_encrypt(blocks[i], blocks[i], &key, BF_DECRYPT);
		*blocks[i] ^= *blocks[i-1];
	}	
	BF_ecb_encrypt(blocks[0], blocks[0], &key, BF_DECRYPT);
	*blocks[0] ^= *iv; // XOR first plaintext block with the Initialization Vector

	// remove padding
	int pad_n = blocks[block_n-1][BLOCKSIZE-1]; // the last byte should give us how many padding bytes were used
	char true_pad = 1;
	for(int i=BLOCKSIZE-1; i>BLOCKSIZE-pad_n; i--) {
		if(blocks[block_n-1][i] != pad_n) {
			true_pad = 0;	
			break;
		}
	}
	
	if(true_pad) *resultlen = bufsize - pad_n;
	else *resultlen = bufsize;

	// convert blocks to char*
	unsigned char* result = new unsigned char[*resultlen];	
	for(int i=0; i<block_n; i++) {
		for(int j=0; j<BLOCKSIZE; j++) {
			if(BLOCKSIZE*i + j >= *resultlen) break;
			memcpy(result + i*BLOCKSIZE + j, blocks[i] + j, 1);
		}
	}

	// free blocks
	for(int i=0; i<block_n; i++) {
		delete[] blocks[i];
	}
	delete[] blocks;
	delete[] iv;

	print_buf("decrypted", result, *resultlen);

	return result;
}

void* fs_decrypt_correct(void* ciphertext, int bufsize, char* keystr, int* resultlen) {
	printf("fs_decrypt_correct()\n");
	//print_buf("ciphertext", (unsigned char*) ciphertext, bufsize);
	int k = get_key_length(keystr);
	print_buf("key", (unsigned char*) keystr, k);

	// sets up the Blowfish key
	BF_KEY key;
	BF_set_key(&key, k, (unsigned char*) keystr); // void BF_set_key(BF_KEY *key, int len, const unsigned char *data);	

	// create Initialization Vector (IV) containing NULL characters
	unsigned char* iv = new unsigned char[BLOCKSIZE]; // allocates 8 bytes
	memset(iv, 0, BLOCKSIZE); // initialize to NULL

	// copy over ciphertext ; will be directly modified here to decrypt 
	unsigned char* result = new unsigned char[bufsize];
	memcpy(result, ciphertext, bufsize);

	//print_buf("to decrypt", result, bufsize);

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

	delete[] iv;

	print_buf("decrypted", result, *resultlen);

	return result;
}
