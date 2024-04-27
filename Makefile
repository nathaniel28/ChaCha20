CFLAGS=-g -Wall -Wextra -pedantic -O3 -march=native
LIBS=

main: main.c
	$(CC) $(CFLAGS) $(LIBS) -o main main.c
