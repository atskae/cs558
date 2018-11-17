/*
	Prevent code from crashing on a segmentation fault
	
	Syracuse University's Meltdown Lab
	http://www.cis.syr.edu/~wedu/seed/Labs_16.04/System/Meltdown_Attack/Meltdown_Attack.pdf
*/

#include <stdio.h>
#include <setjmp.h> //sigjump_buf
#include <signal.h> // signal handler

static sigjmp_buf jbuf;

// signal handler on a segmentation fault
static void catch_segv() {
	// siglongjmp(sigjump_buf, return value)
	siglongjmp(jbuf, 1); // return to the checkpoint set when sigsetjump() was called ; restores context
	// return val is 1 so that the if statement goes to the else clause when returning
}

int main(int argc, char* argv[]) {

	unsigned long kernel_addr = 0x00000000b00bcc9b; // address of secret value in kernel space

	// register signal handler for seg fault
	signal(SIGSEGV, catch_segv);

	// creates a checkpoint ; context is saved in sigjump_buf jbuf
	if(sigsetjmp(jbuf, 1) == 0) {  // return 0 if checkpoint was set up ; returns non-zero if returning from siglongjump()
		// cause seg fault
		char kernel_byte = *(char*)kernel_addr;
		printf("Look at me!!! I got the secret! %c\n", kernel_byte); // should never execute
	} else {
		printf("When would I go here...? Also, MEMORY ACCESS VIOLATION!\n");
	}

	printf("I'm hungry... agh, gotta keep programmin'\n");
	printf("Nah.\n");

	return 0;
}
