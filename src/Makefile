CC=gcc
LIBS=libnl-3.0 libnl-genl-3.0
override CFLAGS+=$(shell pkg-config --cflags $(LIBS)) --std=gnu11 -Wall
LDLIBS=$(shell pkg-config --libs $(LIBS)) -ldl

.PHONY: all clean plugins

all: main plugins

plugins: echo.so

clean:
	rm -f main *.o *.so

main: main.o

%.so: %.o
	$(CC) -shared $^ -o $@
