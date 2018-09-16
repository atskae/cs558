#include <stdlib.h> 
#include <stdio.h>
#include <unistd.h> // getopt
#include <stdint.h> // ensures byte-sizes of data types
#include <ctype.h> // tolower()
#include <string.h> 

/*

	RC6 components

*/
#define ENCRYPT 1
#define DECRYPT 0

#define WORD_SIZE 32
#define NUM_ROUNDS 20

// RC6-w/r/b ; RC6-<word_size>/<num_rounds>/<key_length>
unsigned char* key = NULL; // can vary in size
int key_size = 0; // in bytes
char action = ENCRYPT;
unsigned char* text = NULL; // text to encrypt or decrypt
int text_size = 0;

// Four 32-bit registers for encryption/decryption
int32_t reg_A = 0x00000000;
int32_t reg_B = 0x00000000;
int32_t reg_C = 0x00000000;
int32_t reg_D = 0x00000000;

// Key schedule for RC6
int32_t round_keys[2*NUM_ROUNDS + 4]; // S array from paper
int32_t P32 = 0xB7E15163; // "magical constant"
int32_t Q32 = 0x9E3779B9; // "magical constant"

/*

	Helper functions

*/

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
	for(int i=0; i<hex_string_size/2; i++) {
		sscanf(pos, "%2hhx", &key[i]);
        	pos += 2;
		key_size++;
	}

	fclose(input);

	// debug
	printf("Text (%i bytes): ", text_size);
	for(int i=0; i<text_size; i++) {
		printf("%02x ", text[i]);
	}
	printf("\nKey (%i bytes): ", key_size);
	for(int i=0; i<key_size; i++) {
		printf("%02x ", key[i]);
	}
	printf("\n");

}

int main(int argc, char* argv[]) {

	if(argc != 3) {
		printf("./rc6 <input.txt> <output.txt>\n");
		exit(1);
	}	

	printf("RC6-32/20/b\n");
	parse_input(argv[1]); // obtain text and user key	
	
	return 0;
}
