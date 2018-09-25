CC=gcc
CFLAGS=-Wall -lm

a1: main.o
	$(CC) main.o $(CFLAGS) -o rc6

main.o: main.c
	$(CC) -c main.c
clean:
	rm *.o rc6
