CC=gcc
CFLAGS=-Wall -g 

all: victim attacker

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

victim: victim.o
	$(CC) victim.o $(CFLAGS) -o victim

attacker: attacker.o
	$(CC) attacker.o $(CFLAGS) -o attacker

clean:
	rm *.o victim attacker
