CC=gcc

TESTDIR=./test
SRC=infect_cxa_finalize.c
BIN=infect_cxa_finalize
CFLAGS=-I. -Wall

ifeq ($(debug), on)
	CFLAGS += -D_DEBUG
endif

.PHONY: clean all

all: $(BIN)
	$(MAKE) -C $(TESTDIR)

$(BIN): $(SRC)
	$(CC) -o $@ $^ $(CFLAGS)

clean:
	-rm $(BIN)
	$(MAKE) -C $(TESTDIR) clean
