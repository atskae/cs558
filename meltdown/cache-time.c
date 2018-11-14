/*
	Syracuse University's Meltdown Lab
	http://www.cis.syr.edu/~wedu/seed/Labs_16.04/System/Meltdown_Attack/Meltdown_Attack.pdf
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include <emmintrin.h> // _mm_clfush()
#include <x86intrin.h>

#define PAGE_SIZE 4096 // in bytes
#define PROBE_N 10 // number of elements

// only probe PROB_N elements ; multiplying by page size ensures that each access to this array
// is on a different memory page ; prevents cache prefetching (the only line that is brought into the cache is the accessed cache line)
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
	for(i=0; i<PROBE_N; i++) {
		// invalidates and flushes the cache line that contains the address from all caches in the cache hierarchy
		_mm_clflush(&probe_array[i * PAGE_SIZE]);
	}
	
	// access some probe_array items ; the next time we access the same items, the access time should be much faster than the
	// accesses to other probe_array items
	probe_array[3 * PAGE_SIZE] = 100; 
	probe_array[7 * PAGE_SIZE] = 200; 

	for(i=0; i<PROBE_N; i++) {
		addr = &probe_array[i * PAGE_SIZE]; 
		start = __rdtscp(&junk); // read time stamp before the memory read
		junk = *addr; // read value
		total_cycles = __rdtscp(&junk) - start;	
		printf("Access time for probe_array[%i * %i]: %llu CPU cycles.\n", i, PAGE_SIZE, total_cycles);
	}

	return 0;
}
