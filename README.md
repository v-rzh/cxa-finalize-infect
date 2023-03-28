# cxa-finalize-infect
An ELF infector that hijacks `__cxa_finalize` function. The parasite
infects the code segment padding (Silvio Cesare's padding method).

## Building
Run `make` or `make debug=on` for a debug build.

## Usage

```bash
[joey@gibson]$ ./infect_cxa_finalize
Usage: ./infect_cxa_finalize [-p] [-d] <parasite.o> <host.elf>

    -p    Hijack __cxa_finalize in .plt.got
    -d    Hijack __cxa_finalize in __do_glob_dtors_aux
```

The infector expects the parasite to be an ELF object file, with all of the
code contained in the `.text` section. At the moment the beginning of code is
also treated as the parasite entry point. Check the `test` directory for some
examples.

The `-d` option is for binaries that were compiled with no PLT, however it
**won't work** if the PLT is present.

## Testing
The `test` directory contains a few very simple parasites and a small
collection of ELF binaries distributed with GNU/Linux compiled with and without
PLT. Run the `run_tests.sh` to infect each binary and test the infection.
