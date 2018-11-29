#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h> // for open
#include <unistd.h>

#define BYTES_PER_LINE 16

static char* pic_bytes = NULL;

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

	pic_bytes = (char*) malloc(bytes_n); // allocate a buffer for image bytes
	printf("Loaded image file (%lu bytes)\n", bytes_n); // in real life, the attacker must find this address themselves...

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
	print_bytes(pic_bytes, 16);

	// open kernel /proc file
	int fd = open("/dev/pic_kernel", O_RDWR); // open for reading and writing
	if(fd < 0) {
		perror("Failed to open /proc file.\n");
		return -1;
	}	

	// write pic_bytes to kernel
	int ret;
	ret = pwrite(fd, pic_bytes, bytes_n, 0); // triggers the proc_read() function in kernel to be executed
	if(ret < 0) perror("Writing failed Que paso?\n");
	ret = pread(fd, NULL, 0, 0); // triggers the proc_read() function in kernel to be executed
	if(ret < 0) perror("Read failed. Que paso?\n");

	printf("Waiting to be attacked... ret=%i\n", ret);
	while(1) {
		ret = pread(fd, NULL, 0, 0);	
	}

	return 0;
}
