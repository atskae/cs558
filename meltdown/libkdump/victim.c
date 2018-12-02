#include <sys/types.h>
#include <unistd.h>

#include "libkdump.h"

char* secret = "Pajama Sam";

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

	// read any virtual address, regardless of kernel/user space
	size_t p_addr = libkdump_virt_to_phys( (size_t) &secret ); // convert to physical addr?	
	//unsigned char val = libkdump_read(addr);
	//printf("Read value: %02x\n", val);

	// cleanup libkdump
	if(libkdump_cleanup() != 0) {
		perror("Failed to cleanup libkdump\n");
		return -1;
	}	

	printf("Victim pid: %i\n", getpid());
	printf("VA: %p, PA: %p\n", &secret, p_addr);	

	while(1) {
		char c = secret[0];
	}

	return 0;
}
