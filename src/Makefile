CC=gcc
LIBS=libnl-3.0 libnl-genl-3.0
override CFLAGS+=$(shell pkg-config --cflags $(LIBS)) --std=gnu11 -Wall
LDLIBS=$(shell pkg-config --libs $(LIBS)) -ldl

.PHONY: all clean

all: main

clean:
	rm -f main *.o

main: main.o
