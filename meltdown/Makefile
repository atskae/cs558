CC=gcc
CFLAGS=-Wall -march=native

all: cache-time flush-reload user exception_handling meltdown_experiment meltdown_experiment2

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

cache-time: cache-time.o
	$(CC) cache-time.o $(CFLAGS) -o cache-time

flush-reload: flush-reload.o
	$(CC) flush-reload.o $(CFLAGS) -o flush-reload

user: user.o
	$(CC) user.o $(CFLAGS) -o user

exception_handling: exception_handling.o
	$(CC) exception_handling.o $(CFLAGS) -o exception_handling

meltdown_experiment: meltdown_experiment.o
	$(CC) meltdown_experiment.o $(CFLAGS) -o meltdown_experiment 

meltdown_experiment2: meltdown_experiment2.o
	$(CC) meltdown_experiment2.o $(CFLAGS) -lkdump -o meltdown_experiment2

clean:
	rm *.o cache-time flush-reload user exception_handling meltdown_experiment meltdown_experiment2 
