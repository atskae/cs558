#include <stdlib.h> 
#include <stdio.h>
#include <unistd.h> // getopt
#include <stdint.h> // ensures byte-sizes of data types
#include <ctype.h> // tolower()
#include <string.h> 
#include <math.h>

/*

	RC6 components

*/
#define ENCRYPT 1
#define DECRYPT 0

#define WORD_SIZE 32 // in bits
#define NUM_ROUNDS 20

// RC6-w/r/b ; RC6-<word_size>/<num_rounds>/<key_length>
char action = ENCRYPT;
unsigned char* key = NULL; // can vary in size
int key_size = 0; // in bytes
unsigned char* text = NULL; // text to encrypt or decrypt
int text_size = 0;

// Four 32-bit registers for encryption/decryption
uint32_t reg_A = 0x00000000;
uint32_t reg_B = 0x00000000;
uint32_t reg_C = 0x00000000;
uint32_t reg_D = 0x00000000;

// Key schedule for RC6
uint32_t round_keys[2*NUM_ROUNDS + 4]; // S array from paper
uint32_t* L; // user-key with zero-byte padding in array format, little-endian format
uint32_t P32 = 0xB7E15163; // "magical constant"
uint32_t Q32 = 0x9E3779B9; // "magical constant"


/*

	Helper functions

*/

void print_bytes(char* name, char* ptr, int num_bytes) {

	printf("%s (%i bytes): ", name, num_bytes);
	for(int i=0; i<num_bytes; i++) {
		printf("%02x ", (unsigned char) ptr[i]);
	}
	printf("\n");

}

void print_uint(char* name, uint32_t* ptr, int num_elem) {

	printf("%s (%i %i-byte elements): ", name, num_elem, WORD_SIZE/8);
	for(int i=0; i<num_elem; i++) {
		printf("%04x ", (unsigned char) ptr[i]);
	}
	printf("\n");

}

void parse_input(char* file) {

	FILE* input = fopen(file, "rb"); // read in binary mode
	if(!input) {
		printf("Failed to open input file.\n");
		exit(1);
	}

	// check if to encrypt or decrypt	
	char buf;
	fread(&buf, 1, 1, input);	
	if(buf == 'E') action = ENCRYPT;
	else action = DECRYPT;

	// debug	
	if(action == ENCRYPT) printf("ENCRYPT\n");
	else printf("DECRYPT\n");

	while(buf != ':') {
		fread(&buf, 1, 1, input);		
	}	
	char* hex_string = (char*) malloc(256);
	memset(hex_string, 0, 256);
	int hex_string_size = 0;	
	// read the user-supplied text as a hex string
	while(buf != '\n') {
		fread(&buf, 1, 1, input);		
		if(buf == ' ' || buf == '\n') continue;	
		hex_string[hex_string_size] = buf;
		hex_string_size++;
	}

	char* pos = hex_string;
	text = (char*) malloc(256);
	memset(text, 0, 256);
	text_size = 0;
	for(int i=0; i<hex_string_size/2; i++) {
		sscanf(pos, "%2hhx", &text[i]);
        	pos += 2;
		text_size++;
	}	

	// obtain key
	while(buf != ':') {
		fread(&buf, 1, 1, input);
	}	
	memset(hex_string, 0, 256);
	hex_string_size = 0;	
	// read the key as a hex string
	while(buf != '\n') {
		fread(&buf, 1, 1, input);		
		if(buf == ' ' || buf == '\n') continue;	
		hex_string[hex_string_size] = buf;
		hex_string_size++;
	}
	pos = hex_string;
	key = (char*) malloc(256);
	memset(key, 0, 256);
	key_size = 0;
		
	L = (uint32_t*) malloc(sizeof(256)/sizeof(uint32_t)); // holds groups of bytes of size WORD_SIZE in little-endian format, with the zero padding
	int L_size = 0;
	memset(L, 0, 256);
	uint32_t mask;
	// read each byte
	for(int i=0; i<hex_string_size/2; i++) {
		sscanf(pos, "%2hhx", &key[i]);
        	mask = 0x00000000; // reset mask
		mask |= key[i]; // mask = 0x 00 00 00 <key>
		mask << 8 * (i%4); // mask = 0x00 <key> 00 00 ; shift left 8*2 = 16 times
		L[i % 4] |= mask; // L[pos] = 0x<b2> <key> <b1> <b0>
		pos += 2;
		key_size++;
	}

	fclose(input);
	L_size = ceil(key_size/(WORD_SIZE/8));
	
	// debug
	print_bytes("Text", text, text_size);
	print_bytes("Key", key, key_size);
	print_uint("L", L, L_size);
}

void run_key_schedule() {

	printf("run_key_schedule()\n");

	printf("run_key_schedule() completed.\n");
}

int main(int argc, char* argv[]) {

	if(argc != 3) {
		printf("./rc6 <input.txt> <output.txt>\n");
		exit(1);
	}	

	printf("RC6-32/20/b\n");
	parse_input(argv[1]); // obtain text and user key	

	run_key_schedule(); // generates 2r + 4 keys in round_keys[]
	
	return 0;
}
