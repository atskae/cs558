#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define BYTES_PER_LINE 32

static unsigned char* pic_bytes = NULL;
static unsigned char* secret_buffer = NULL;

void access_bytes(unsigned char* bytes, int bytes_n) {
	if(!secret_buffer || !bytes) {
		printf("No buffer to copy.\n");
		return;
	}

	memcpy(secret_buffer, bytes, bytes_n);	
	printf("Waiting to be attacked...\n");
	while(1); // waiting to be attacked
}

void print_bytes(unsigned char* bytes, int bytes_n) {
	if(!bytes) {
		printf("No bytes to read.\n");
		return;
	}

	int i;
	for(i=0; i<bytes_n; i++) {
		printf("%02x ", bytes[i]);
		if(i % BYTES_PER_LINE == 0) printf("\n");
	}
	if(bytes_n % BYTES_PER_LINE) printf("\n");
	printf("Total bytes: %i\n", bytes_n);
}

long read_bytes(char* file) {
	
	FILE* fd = fopen(file, "rb"); // open the image file
	if(!fd) {
		perror("Failed to load picture.\n");
		return -1;
	}
	printf("%s loaded.\n", file);

	// get file bytes_n
	fseek(fd, 0, SEEK_END); // goes to the end of file
	long bytes_n = ftell(fd); // read the position in the file

	pic_bytes = (unsigned char*) malloc(bytes_n); // allocate a buffer for image bytes
	printf("Loaded image file (%lu bytes) at address %p\n", bytes_n, pic_bytes); // in real life, the attacker must find this address themselves...

	rewind(fd); // move to beginning of file
	fread(pic_bytes, 1, bytes_n, fd); // read file contents
	fclose(fd); // close image file

	return bytes_n;
}

int main(int argc, char* argv[]) {

	if(argc < 2) {
		printf("./victim <picture file>\n");
		return 1;
	}

	char* pic_file = argv[1];
	long bytes_n = read_bytes(pic_file); // sets pic_bytes to buffer of image file bytes
	
	// print_bytes(pic_bytes, bytes_n);
	secret_buffer = (unsigned char*) malloc(bytes_n);
	access_bytes(pic_bytes, bytes_n);

	return 0;
}
