CC=gcc
NASM=nasm
PARASITE=shell.o bigboy.o hello.o
HOST=dummy_host.elf
NASM_FLAGS=-felf64

.PHONY: all clean

all: $(PARASITE)

%.elf: %.c
	$(CC) -o $@ $^

%.o: %.asm
	$(NASM) $(NASM_FLAGS) -o $@ $^

clean:
	-rm $(PARASITE)

