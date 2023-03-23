CC=gcc

SRC=infect_cxa_finalize.c
BIN=infect_cxa_finalize
CFLAGS=-I. -Wall

.PHONY: clean all

all: $(BIN)

$(BIN): $(SRC)
	$(CC) -o $@ $^ $(CFLAGS)
	cp empty_backup.elf empty.elf

clean:
	-rm $(BIN)
