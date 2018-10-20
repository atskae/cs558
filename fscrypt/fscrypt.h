#include "openssl/blowfish.h"

// Block size for blowfish in bytes
const int BLOCKSIZE = 8; 

// encrypt plaintext of length bufsize. Use keystr as the key.
void* fs_encrypt(void* plaintext, int bufsize, char* keystr, int* resultlen);
void* fs_encrypt_correct(void* plaintext, int bufsize, char* keystr, int* resultlen); // used to check my work

// decrypt ciphertext of length bufsize. Use keystr as the key.
void* fs_decrypt(void* ciphertext, int bufsize, char* keystr, int* resultlen);
void* fs_decrypt_correct(void* ciphertext, int bufsize, char* keystr, int* resultlen); // used to check my work
