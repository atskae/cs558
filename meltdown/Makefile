CC=gcc
CFLAGS=-Wall -march=native

all: cache-time

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

cache-time: cache-time.o
	$(CC) cache-time.o -o cache-time


clean:
	rm *.o cache-time
