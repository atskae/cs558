#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h> // for open
#include <unistd.h>

static char* str = "Pajama Sam";

int main(int argc, char* argv[]) {

	printf("str at %p, my pid: %i\n", str, getpid());
	while(1) {
	}

	return 0;
}
