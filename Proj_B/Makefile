CC=gcc
CFLAGS=-g -Wall -std=gnu99 -lpthread -lm -D_POSIX_PTHREAD_SEMANTICS 
LDFLAGS=

all: projb

projb: pjb.o tun.o 
	$(CC) $^ $(LDFLAGS) -o $@ -lpthread -lm

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)
clean:
	rm -f projb *.o *.out
