Benchmark testsuite
===================

Run `make` and compare results with runs of previous commits.

## String matching macros

After building radare2, compare all four `R_STR_*_ANY` macros against loops and
literal OR chains:

```sh
make -B str_any STR_ANY_CFLAGS=-O2
LD_LIBRARY_PATH=../../libr/util DYLD_LIBRARY_PATH=../../libr/util ./str_any > str_any.csv
```

Repeat with `STR_ANY_CFLAGS=-O0` for an unoptimized build. Times are nanoseconds
per lookup; ratios above 1 mean the macro is slower. `./str_any 256` doubles the
default repetitions. Remove the executable with `make clean-str-any`.

The datasets are six sanitizer prefixes, four SHA names, and eighteen format
function names. Each runs with 0%, 50%, and 100% hits. Inputs are allocated at
runtime and shuffled deterministically. Misses alter the first or last character
of an entry. Prefix hits append text; suffix and substring hits extract part
of an entry. The latter two operations search for the key inside each entry.

Every result is checked before timing. Matchers cannot be inlined into the
timing loop; their helpers can still be inlined. Method order rotates over
five trials, and the best time is reported. Suffix baselines compute the key
length once per lookup. These are synthetic lookup timings, not measurements
of total application performance.
