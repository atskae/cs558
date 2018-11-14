/*
	Syracuse University's Meltdown Lab
	http://www.cis.syr.edu/~wedu/seed/Labs_16.04/System/Meltdown_Attack/Meltdown_Attack.pdf
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include <emmintrin.h> // _mm_clfush()
#include <x86intrin.h>

#define PAGE_SIZE 4096 // in bytes ; separating each probe_array element by PAGE_SIZE ensures that no two elements that we access will be in the same cache block
#define PROBE_N 256 // a byte value can be one of 256 possible values 
#define CACHE_HIT_THRESHOLD 100 // if the number of cycles is less than CACHE_HIT_THRESHOLD, the access was a cache hit ; number determined by running cache-time

#define ITER_N 100 // number of times to run experiment

char secret = 'x'; 
uint8_t probe_array[PROBE_N * PAGE_SIZE];
int correct = 0;

void flush_array() {

	int i;
	// flush probe_array from CPU cache
	for(i=0; i<PROBE_N; i++) {
		// invalidates and flushes the cache line that contains the address from all caches in the cache hierarchy
		_mm_clflush(&probe_array[i * PAGE_SIZE]);
	}

}

void victim_run() {
	probe_array[secret * PAGE_SIZE] = 20;
}

void reload_array() {
	
	// time accesses to each element in the probe_array	
	unsigned int junk = 0; // ???
	register uint64_t start, total_cycles;
	volatile uint8_t* addr; // 8-bit pointer = byte pointer

	char guess = '?';

	int i;
	for(i=0; i<PROBE_N; i++) {
		addr = &probe_array[i * PAGE_SIZE]; 
		start = __rdtscp(&junk); // read time stamp before the memory read
		junk = *addr; // read value
		total_cycles = __rdtscp(&junk) - start;	
		if(total_cycles < CACHE_HIT_THRESHOLD) guess = i;
	}

	if(guess == secret) correct++;
	printf("Guessed secret value: %c\n", guess);

}

int main(int argc, char* argv[]) {

	// initialize the probe_array
	int i, iter;
	for(i=0; i<PROBE_N; i++) { // only going down a single column in probe array ; these are the only elements we access
		probe_array[i * PAGE_SIZE] = 1;	
	}

	for(iter=0; iter<ITER_N; iter++) {
		flush_array(); // removes the entire array from all levels of cache
		victim_run(); // victim accesses one of the elements in probe_array
		reload_array(); // bring in all probe_array elements into the cache and time each access
	}

	printf("Secret byte: %c\n", secret);
	printf("Correct %i out of %i iterations (%.2f%% correct)\n", correct, ITER_N, (float)correct/ITER_N * 100);
	
	return 0;
}
