.PHONY: all, clean
CFLAGS = -Wall -g
CGG = gcc
CXX = g++

PROGS = hw4 

all: ${PROGS}

hw4: hw4.c helper.h command.h
	$(CGG) -o $@ $(CFLAGS) $< -lcapstone 

clean:
	rm -f *~ $(PROGS)