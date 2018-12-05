#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h> // for open
#include <unistd.h>

#define BYTES_PER_LINE 16

static unsigned char* pic_bytes = NULL;

void print_bytes(unsigned char* bytes, int bytes_n) {
	if(!bytes) {
		printf("No bytes to read.\n");
		return;
	}

	int i;
	for(i=0; i<bytes_n; i++) {	
		if(i != 0 && i % BYTES_PER_LINE == 0) printf("\n");
		printf("%02x ", (unsigned char) bytes[i]);
	}
	printf("\n");
	printf("Printed %i bytes\n", bytes_n);
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
	printf("Loaded image file (%lu bytes ; %lu KB)\n", bytes_n, bytes_n/1024); 

	rewind(fd); // move to beginning of file
	fread(pic_bytes, 1, bytes_n, fd); // read file contents
	fclose(fd); // close image file

	return bytes_n;
}

int main(int argc, char* argv[]) {

	if(argc != 2 && argc != 3) {
		printf("./victim <picture file> <num bytes to print>\n");
		return 1;
	}

	char* pic_file = argv[1];
	int read_bytes_n = 0;
	if(argv[2]) read_bytes_n = atoi(argv[2]);

	long bytes_n = read_bytes(pic_file); // sets pic_bytes to buffer of image file bytes	
	print_bytes(pic_bytes, read_bytes_n);

	printf("My pid: %i\n", getpid());
	while(1) {
	}

	return 0;
}
