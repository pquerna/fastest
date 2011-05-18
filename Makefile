CFLAGS=-O0 -g -I. -DEV_MULTIPLICITY=0 -Wall
CC?=gcc

fastest: fastest.o
	$(CC) $(CFLAGS) fastest.o http-parser/http_parser.o libuv/uv.a libuv/ev/.libs/libev.a -o fastest

fastest.o: fastest.c
	$(CC) $(CFLAGS) -c fastest.c -o $@

clean:
	rm -f *.o fastest

.PHONY: clean
