.PHONY: all, clean
CFLAGS = -Wall -g
CGG = gcc

PROGS = debugger

all: ${PROGS}

debugger: debugger.c
	$(CGG) -o $@ $(CFLAGS) $< 

clean:
	rm -f *~ $(PROGS)