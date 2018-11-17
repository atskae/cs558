#include <stdio.h>

int main() {

	char* kernel_addr = (char*)0x00000000b00bcc9b; 
	char kernel_byte = *kernel_addr;
	printf("Did I get the secret??? %c\n", kernel_byte);

	return 0;
}
