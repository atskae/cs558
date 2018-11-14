CC=gcc
CFLAGS=-Wall -march=native

all: cache-time flush-reload

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

cache-time: cache-time.o
	$(CC) cache-time.o $(CFLAGS) -o cache-time

flush-reload: flush-reload.o
	$(CC) flush-reload.o $(CFLAGS) -o flush-reload

clean:
	rm *.o cache-time flush-reload
