CC=gcc
CFLAGS=-Wall -g 
LIBS=-lkdump

all: attacker victim

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS) $(LIBS)

attacker: attacker.o
	$(CC) attacker.o $(CFLAGS) $(LIBS) -o attacker

victim: victim.o
	$(CC) victim.o $(CFLAGS) $(LIBS) -o victim

clean:
	rm *.o attacker victim
