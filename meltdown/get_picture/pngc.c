#include <stdio.h>

/* Attempts to clean a corrupted png file */

unsigned char png_sig[8] = {0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a};

int main(int argc, char* argv[]) {

	if(argc != 2) {
		printf("./clean <.png file>\n");
		return 1;
	}

	FILE* fd = fopen(argv[1], "w+");
	if(fd < 0) {
		perror("Failed to open file.\n");
		return 1;
	}

	// write png signature to file, if corrupted
	//fwrite(fd, &png_sig, 8);		
	fclose(fd);

	return 0;
}
