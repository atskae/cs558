#include <stdlib.h> 
#include <stdio.h>
#include <unistd.h> // getopt
#include <stdint.h> // ensures byte-sizes of data types
#include <ctype.h> // tolower()
#include <string.h> 
#include <math.h>

#include <time.h> // rand()

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
#define REG_A 0
#define REG_B 1
#define REG_C 2
#define REG_D 3
uint32_t regs[4] = { 0x00000000, 0x00000000, 0x00000000, 0x00000000};

// Key schedule for RC6
uint32_t round_keys[2*NUM_ROUNDS + 4]; // S array from paper
uint32_t* L; // user-key with zero-byte padding in array format, little-endian format
uint32_t L_size;
const uint32_t P32 = 0xB7E15163; // "magical constant"
const uint32_t Q32 = 0x9E3779B9; // "magical constant"


/*

	Helper functions

*/

void print_bits(char* name, uint32_t val, int num_bits) {
	
	printf("(%s) %08x = ", name, val);
	uint32_t mask;
	for(int i=num_bits-1; i>=0; i--) {
		mask = 1 << i;
		if(val & mask) printf("1");
		else printf("0");
		if(i % 4 == 0) printf(" ");	
	}
	printf("\n");
}

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
		printf("%08x ", (uint32_t) ptr[i]);
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
		
	L = (uint32_t*) malloc(256 * sizeof(uint32_t)); // holds groups of bytes of size WORD_SIZE in little-endian format, with the zero padding
	memset(L, 0, 256*sizeof(uint32_t) );
	uint32_t mask;
	// read each byte
	for(int i=0; i<hex_string_size/2; i++) {
		sscanf(pos, "%2hhx", &key[i]);
        	mask = 0x00000000; // reset mask
		mask |= key[i]; // mask = 0x 00 00 00 <key>	
		mask = mask << (8 * (i%4)); // mask = 0x00 <key> 00 00 ; shift left 8*2 = 16 times
	//	printf("mask: %08x (val %02x)\n", mask, key[i]);
		L[ (int)floor(i/4) ] |= mask; // L[pos] = 0x<b2> <key> <b1> <b0>
	//	printf("L[%i] = %08x\n", (int)floor(i/4), L[(int)floor(i/4)] );
		pos += 2;
		key_size++;
	}

	fclose(input);
	L_size = ceil((float)key_size/(WORD_SIZE/8));
		
	// debug
	print_bytes("Text", text, text_size);
	print_bytes("Key", key, key_size);
	print_uint("L", L, L_size);
}

// ROTATES a to the left by the amount given by the least significant log2(WORD_SIZE) bits
uint32_t rotatel(uint32_t a, uint32_t b) {

	uint32_t s = b & ~(0xFFFFFFE0); // extract the log2(WORD_SIZE) = 5 least significant bits
	//printf("a: %u, b: %u, ROTATE a to the left by %i bits (%06x)\n", a, b, s, s);	
	uint32_t mask;
	//print_bits("a", a, 32);
	//print_bits("b", b, 32);
	//print_bits("s", s, 32);
	
	for(uint32_t i=0; i<s; i++) {
		// read the most significant BIT and move it to the least significant bit
		mask = (a & ~(0x7FFFFFFF)) >> (WORD_SIZE - 1);
		//print_bits("most sig bit", mask, 32);	
		a = a << 1; // move to the left by 1 bit
		//print_bits("after shift by 1 bit left", a, 32);	
		a |= mask; // write buf to the least significant bit
		//printf("%i) ", i);
		//print_bits("a", a, 32);
	}
	//print_bits("after rotate", a, 32);	
	//printf("\n\n");	
	
	return a;
}

// ROTATES a to the right by the amount given by the least significant log2(WORD_SIZE) bits
uint32_t rotater(uint32_t a, uint32_t b) {

	uint32_t s = b & ~(0xFFFFFFE0); // extract the log2(WORD_SIZE) = 5 least significant bits
	//printf("a: %u, b: %u, ROTATE a to the right by %i bits (%06x)\n", a, b, s, s);	
	uint32_t mask;
	//print_bits("a", a, 32);
	//print_bits("b", b, 32);
	//print_bits("s", s, 32);
	
	for(uint32_t i=0; i<s; i++) {
		// read the least significant BIT and move it to the most significant bit
		mask = (a & ~(0xFFFFFFFE)) << (WORD_SIZE - 1);
		//print_bits("most sig bit", mask, 32);	
		a = a >> 1; // move to the right by 1 bit
		//print_bits("after shift by 1 bit left", a, 32);	
		a |= mask; // write buf to the most significant bit
		//printf("%i) ", i);
		//print_bits("a", a, 32);
	}
	//print_bits("after rotate", a, 32);	
	//printf("\n\n");	
	
	return a;
}

//uint32_t mod(uint32_t val) {
//	return val % (unsigned long long) pow(2, WORD_SIZE);
//}

void run_key_schedule() {

	//printf("\n\nrun_key_schedule()\n");	
	round_keys[0] = P32;	
	for(uint32_t i=1; i<=2*NUM_ROUNDS+3; i++) {	
		round_keys[i] = round_keys[i-1] + Q32;
	}
	
	uint32_t i=0, j=0, A=0, B=0;		

	uint32_t max = 2*NUM_ROUNDS + 4;
	if(L_size > max) max = L_size;
	uint32_t v = 3 * max;
	
	for(uint32_t s=1; s<=v; s++) {

		round_keys[i] = rotatel( round_keys[i] + A + B, 3);
		A = round_keys[i];
	
		L[j] = rotatel( L[j] + A + B, A + B);
		B = L[j];
	
		i = (i+1) % (2*NUM_ROUNDS + 4);
		j = (j+1) % L_size;
	}

	print_uint("After key schedule", round_keys, 2*NUM_ROUNDS + 4);
	//printf("run_key_schedule() completed.\n");
}

void partition(unsigned char* text) {
	uint32_t mask;
	int wb = WORD_SIZE/8;
	for(int i=0; i<text_size; i++) { // for each byte in the text
		mask = 0x00000000; // reset mask
		mask |= text[i]; // mask = 0x 00 00 00 <b>	
		mask = mask << (8 * (i % wb)); // mask = 0x00 <b> 00 00 ; shift left 8*2 = 16 times
		regs[ (int)floor(i/wb) ] |= mask; // regs[r] = 0x<b2> <b> <b1> <b0>
	}

	print_uint("Registers after partition text", regs, 4);	
}

void encrypt() {
	printf("encrypt()\n");
	printf("A=%08x, B=%08x, C=%08x, D=%08x\n", regs[REG_A], regs[REG_B], regs[REG_C], regs[REG_D]);

	regs[REG_B] = regs[REG_B] + round_keys[0]; 
	regs[REG_D] = regs[REG_D] + round_keys[1];

	uint32_t logw = log2(WORD_SIZE);
	printf("logw %u\n", logw);
	for(int i=1; i<=NUM_ROUNDS; i++) {

		uint32_t t = rotatel( regs[REG_B] * (2*regs[REG_B] + 1), logw);
		uint32_t u = rotatel( regs[REG_D] * (2*regs[REG_D] + 1), logw);
		regs[REG_A] = rotatel(regs[REG_A] ^ t, u) + round_keys[2*i];
		regs[REG_C] = rotatel(regs[REG_C] ^ u, t) + round_keys[2*i + 1];

		uint32_t old_regs[4];
		old_regs[REG_A] = regs[REG_A];
		old_regs[REG_B] = regs[REG_B];
		old_regs[REG_C] = regs[REG_C];
		old_regs[REG_D] = regs[REG_D];

		regs[REG_A] = old_regs[REG_B];
		regs[REG_B] = old_regs[REG_C];
		regs[REG_C] = old_regs[REG_D];
		regs[REG_D] = old_regs[REG_A];

	}

	regs[REG_A] = regs[REG_A] + round_keys[2*NUM_ROUNDS + 2];
	regs[REG_C] = regs[REG_C] + round_keys[2*NUM_ROUNDS + 3];
	
	print_uint("Encrypted", regs, 4);
}

void decrypt() {
	printf("decrypt()\n");	
	printf("ciphertext: A = %08x, B = %08x, C = %08x, D = %08x\n", regs[REG_A], regs[REG_B], regs[REG_C], regs[REG_D]);
	print_uint("Round keys", round_keys, 2*NUM_ROUNDS + 4);

	printf("%u - %u = ", regs[REG_C], round_keys[2*NUM_ROUNDS+3]);
	regs[REG_C] = regs[REG_C] - round_keys[2*NUM_ROUNDS + 3];
	printf("%u\n", regs[REG_C]);	
	regs[REG_A] = regs[REG_A] - round_keys[2*NUM_ROUNDS + 2];

	uint32_t logw = log2(WORD_SIZE);
	for(uint32_t i=NUM_ROUNDS; i>=1; i--) {

		uint32_t old_regs[4];
		old_regs[REG_A] = regs[REG_A];
		old_regs[REG_B] = regs[REG_B];
		old_regs[REG_C] = regs[REG_C];
		old_regs[REG_D] = regs[REG_D];
	
		// parallel assignment	
		regs[REG_A] = old_regs[REG_D];
		regs[REG_B] = old_regs[REG_A];
		regs[REG_C] = old_regs[REG_B];
		regs[REG_D] = old_regs[REG_C];

		uint32_t u = rotatel(regs[REG_D] * (2*regs[REG_D]+1), logw);
		uint32_t t = rotatel(regs[REG_B] * (2*regs[REG_B]+1), logw);	
		regs[REG_C] = rotater(regs[REG_C] - round_keys[2*i+1], t) ^ u;
		regs[REG_A] = rotater(regs[REG_A] - round_keys[2*i], u) ^ t;
	
	}

	regs[REG_D] = regs[REG_D] - round_keys[1];
	regs[REG_B] = regs[REG_B] - round_keys[0];
	
	printf("after decryption: A = %08x, B = %08x, C = %08x, D = %08x\n", regs[REG_A], regs[REG_B], regs[REG_C], regs[REG_D]);
}

int main(int argc, char* argv[]) {

	if(argc != 3) {
		printf("./rc6 <input.txt> <output.txt>\n");
		exit(1);
	}	

//	srand(time(NULL));
//	uint32_t a = rand();
//	uint32_t b = rand();
//	printf("%u + %u = %u\n", a, b, mod(a+b));
//	printf("%u - %u = %u\n", a, b, mod(a-b));
//	printf("%08x XOR %08x = %08x\n", a, b, mod(a^b));
//	printf("%u * %u = %u\n", a, b, mod(a*b));
//	printf("%08x <<< %08x = %08x\n", a, b, rotatel(a,b));
//	print_bits("a", a, 32);
//	print_bits("b", b, 32);
//	print_bits("rotate(a by b)", rotatel(a,b), 32);
//	
//
	printf("RC6-32/20/b\n");
	parse_input(argv[1]); // obtain text and user key	

	run_key_schedule(); // generates 2r + 4 keys in round_keys[]
	partition(text); // partitions plaintext or cipher text into the 4 registers in little-endian format	
	
	if(action == ENCRYPT) encrypt();
	else decrypt();

	return 0;
}
