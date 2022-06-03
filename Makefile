.PHONY: all, clean
CFLAGS = -Wall -g
CGG = gcc
CXX = g++

PROGS = debugger

all: ${PROGS}

debugger: debugger.c helper.h command.h
	$(CGG) -o $@ $(CFLAGS) $< -lcapstone 

clean:
	rm -f *~ $(PROGS)