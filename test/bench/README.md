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

## Noreturn CFG chopping

`noreturn.py` compares installed build prefixes using fresh processes. It times
`aanr` after untimed `aa`, or `aaa` after startup. It disables user initialization
and shared plugins, selects each prefix's libraries explicitly, rotates build
order, discards one warmup per build and command, and records five trials.
`wall_s` measures the command, including pipe transport. `peak_rss_mib` is the
whole process's peak RSS, including startup, setup, the command, the `aflj`
summary and shutdown. The runner uses POSIX `wait4` and needs no Python packages.

Build each revision with identical options and preserve its executables and
libraries in a separate prefix before rebuilding. Symlinks to a shared checkout
must be replaced by copies. On macOS, verify loaded libraries with
`DYLD_PRINT_LIBRARIES=1`; on Linux, use `LD_DEBUG=libs`.

```sh
python3 test/bench/noreturn.py \
  --build master=/tmp/r2-master \
  --build original-pr=/tmp/r2-original-pr \
  --build optimized=/tmp/r2-optimized \
  --output noreturn-default.csv \
  test/bins/elf/dwarf_rust_bubble \
  test/bins/elf/pumasim \
  test/bins/mach0/rust/rust_nonnull_arm64
```

### Recorded comparison (2026-10-05)

The reference run used an Apple M1 Max, macOS 26.5.2, Apple clang 21.0.0,
`-O2` and Capstone 5. Master was `d5717f0658`; the original PR was
`cc76838309`, rebased onto that master as `c9c3bed4a8`. The optimized build
uses this PR's implementation. Each variant was built from the root with the
same configuration, then copied into a separate prefix. The master build used
`sys/install.sh --without-pull`; the other variants reused its configuration.
The loaded master libraries were checked with `DYLD_PRINT_LIBRARIES=1`.

Fixtures come from radare2-testbins commit
`e909ed6dbbf7a2e6563c23c7e126ad3cca0301c3`:

| Fixture | Bytes | SHA-256 |
| --- | ---: | --- |
| `elf/dwarf_rust_bubble` | 7,330,184 | `5916bc0cb2d4bced3169a2601804e86d19b8dc4f12178192c5937822dc25697b` |
| `elf/pumasim` | 9,508,376 | `446d5a77b7aa3cd2139b22492919ebfa2fbcb3205208e12c5a5ed2a3454b13c2` |
| `mach0/rust/rust_nonnull_arm64` | 444,408 | `a85c13d4340d144aeef114778dc520227bb16793ab46022cb349098ed049f320` |
