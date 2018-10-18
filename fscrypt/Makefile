CC=g++
CFLAGS=-Wall -g -lcrypto
DEPS= fscrypt.h

%.o: %.cc $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

all: main.o fscrypt.o
	$(CC) main.o fscrypt.o $(CFLAGS) -o fscrypt

clean:
	rm *.o fscrypt
