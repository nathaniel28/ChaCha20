CFLAGS=-g -Wall -Wextra -pedantic -O3 #-mavx2
LIBS=

main: main.c chacha20.h
	$(CC) $(CFLAGS) $(LIBS) -o main main.c
