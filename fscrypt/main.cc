#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "fscrypt.h"

int main() {

	// printf("fscrypt\n");
	
	//char s[] = "hello world";
	char s[] = "Hallo Welt! Wie geht es dir? Es geht mir gut.";
	char *outbuf_correct, *recvbuf_correct;
	char *outbuf, *recvbuf;
	char pass[] = "top secret omg!!111";
	int len = 0;
	int len_t = 0;
	//int recvlen = 0;
	int recvlen_t = 0;
	
	outbuf_correct= (char *) fs_encrypt_correct((void *) s, strlen(s)+1, pass, &len);
	printf("%s %d\n", "correct length after encryption = ", len);
	
	outbuf = (char *) fs_encrypt((void *) s, strlen(s)+1, pass, &len_t);
	printf("%s %d\n", "length after encryption = ", len_t);
	
	//recvbuf_correct = (char *) fs_decrypt_correct((void *) outbuf_correct, len, pass, &recvlen);	
	//printf("%s %d\n", "correct length after encryption = ", recvlen);

	recvbuf = (char *) fs_decrypt((void *) outbuf, len_t, pass, &recvlen_t);	
	printf("%s %d\n", "length after encryption = ", recvlen_t);

	assert(memcmp(s, recvbuf, recvlen_t) == 0);
	assert((unsigned int)recvlen_t == (strlen(s) + 1));
	printf("received plaintext = %s\n", recvbuf);

	delete[] outbuf_correct;
	delete[] outbuf;
	delete[] recvbuf;
	
	return 0;	
}
