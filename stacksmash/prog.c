#include <stdio.h>
#include <stdlib.h>

void geheimnis() {
	printf("Kannst du etwas geheim halten? :)\n");
	exit(0);
}

void prompt() {
	float garbage = 0.56;
	float mull = 5.50006;
	char buf[2001];
	int b = 9;
	int a = b + 8;	
	gets(buf);
	printf("You entered: %s\n", buf);
}

void pikachu() {
	printf("Pika!!!!\n");
	exit(0);
}

void fakeprompt() {
	prompt();
}

int main() {	
	fakeprompt();
	return 0;
}

void target() {
	printf("Ha! You got pwned!\n");
	exit(0);
}
