CC=gcc

SRC=infect_cxa_finalize.c
BIN=infect_cxa_finalize
CFLAGS=-I. -Wall -D_DEBUG

.PHONY: clean all

all: $(BIN)

$(BIN): $(SRC)
	$(CC) -o $@ $^ $(CFLAGS)

clean:
	-rm $(BIN)
