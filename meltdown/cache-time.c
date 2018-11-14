#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include <emmintrin.h> // _mm_clfush()
#include <x86intrin.h>

#define PAGE_SIZE 4096 // in bytes
#define PROBE_N 10

// only probe PROB_N elements ; multiplying by page size ensures that each access to this array
// is on a different memory page
uint8_t probe_array[PROBE_N * PAGE_SIZE]; 	

int main(int argc, char* argv[]) {

	// time accesses to each element in the probe_array	
	unsigned int junk = 0; // ???
	register uint64_t start, total_cycles;
	volatile uint8_t* addr; // 8-bit pointer = byte pointer

	// initialize the probe_array
	int i;
	for(i=0; i<PROBE_N; i++) { // only going down a single column in probe array ; these are the only elements we access
		probe_array[i * PAGE_SIZE] = 1;	
	}

	// flush probe_array from CPU cache
	for(i=0; i<10; i++) {
		// invalidates and flushes the cache line that contains address from all caches in the cache hierarchy
		_mm_clflush(&probe_array[i * PAGE_SIZE]);
	}
	
	// access some probe_array items ; the next time we access the same items, the access time should be much faster than the
	// accesses to other probe_array items
	probe_array[3 * PAGE_SIZE] = 50;
	probe_array[7 * PAGE_SIZE] = 30;

	for(i=0; i<PROBE_N; i++) {
		addr = &probe_array[i * PAGE_SIZE]; 
		start = __rdtscp(&junk); // read time stamp before the memory read
		junk = *addr;
		total_cycles = __rdtscp(&junk) - start;	
		printf("Access time for probe_array[%i * %i]: %lu CPU cycles.\n", i, PAGE_SIZE, total_cycles);
	}

	return 0;
}
