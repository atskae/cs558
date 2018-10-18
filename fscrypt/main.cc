#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "fscrypt.h"

int main() {

	printf("fscrypt\n");
	
	char s[] = "hello world";
	char *outbuf, *recvbuf;
	char pass[] = "top secret";
	int len = 0;
	int recvlen = 0;
	
	outbuf = (char *) fs_encrypt((void *) s, strlen(s)+1, pass, &len);
	printf("%s %d\n", "length after encryption = ", len);
	
	int i = 0;
	printf("ciphertext = ");
	for (i = 0; i < len; i++)
	    printf("%02x", (unsigned char) outbuf[i]);
	printf("\n");
	
	recvbuf  = (char *) fs_decrypt((void *) outbuf, len, pass, &recvlen);
	assert(memcmp(s, recvbuf, recvlen) == 0);
	assert(recvlen == (strlen(s) + 1));
	printf("plaintext = %s\n", recvbuf);
	
	return 0;	
}
