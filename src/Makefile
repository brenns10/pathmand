CC=gcc
LIBS=libnl-3.0 libnl-genl-3.0
CFLAGS=$(shell pkg-config --cflags $(LIBS)) --std=gnu11 -Wall -Werror -pedantic
LDLIBS=$(shell pkg-config --libs $(LIBS))

.PHONY: all clean

all: main

clean:
	rm -f main *.o

main: main.o
