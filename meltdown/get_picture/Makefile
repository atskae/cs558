CC=gcc
CFLAGS=-Wall -g 

all: victim attacker pngc

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

victim: victim.o
	$(CC) victim.o $(CFLAGS) -o victim

attacker: attacker.o
	$(CC) attacker.o $(CFLAGS) -o attacker

pngc: pngc.o
	$(CC) pngc.o $(CFLAGS) -o pngc

clean:
	rm *.o victim attacker pngc
