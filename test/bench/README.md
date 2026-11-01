Benchmark testsuite
===================

Run `make` and compare results with runs of previous commits.

## String pools

After building radare2, run `make -C test/bench strpool` and then:

```sh
LD_LIBRARY_PATH="$PWD/libr/util" DYLD_LIBRARY_PATH="$PWD/libr/util" test/bench/strpool
```

The benchmark checks returned positions and reports total microseconds and
index bytes for distinct appends, duplicate appends, rebuilding a duplicate
pool after `r_strpool_lock`, and distinct deduplicating adds. It runs increasing
pool sizes to expose quadratic rebuilds. Append timings include string copying
and, for distinct names, formatting. Rebuild timings include only the first
lookup after releasing the index. Append-only index bytes are measured before
any lookup. These are synthetic timings, not whole-application measurements.

For a before/after comparison, copy the original utility library to a separate
directory before rebuilding and select it with the same library-path variables.
Use identical library build flags and repeat runs to account for timing noise.
Remove the executable with `make -C test/bench clean-strpool`.

## ANSI cropping

`ansi_crop.c` compares two built versions of `r_str_ansi_crop`. Preserve the
original utility library before rebuilding with the patch. Build both versions
with the same compiler and optimization flags; for example, configure with
`./configure CFLAGS=-O2`, then run `make -j2` from the repository root.

From `test/bench`, on macOS:

```sh
make ansi_crop
./ansi_crop /tmp/libr_util-before.dylib ../../libr/util/libr_util.dylib
```

On Linux, use the corresponding `.so` paths and set
`LD_LIBRARY_PATH=../../libr/util` for the benchmark executable. Keep copies of
the actual library files, since symlinks into a rebuilt checkout change with it.
The benchmark rejects two paths resolving to the same function.

Each dataset is checked for identical output before timing. The timed work is
one crop plus `free`, including the crop's allocation. Inputs are prepared
outside timing. Each case calibrates its iteration count against the baseline,
then alternates execution order over seven trials and reports median nanoseconds
per call. Datasets cover empty/short strings, panel titles, plain and colored
panels, scrolling, UTF-8, dense color changes, a 1 MiB line, and the top/bottom
of a 10,000-line buffer. These are function timings, not whole-application FPS.
Remove the benchmark executable with `make clean-ansi-crop`.

### Recorded comparison (2026-10-19)

Apple M1 Max, macOS 27.0.1, Apple clang 21.0.0, `-O2`. Both libraries were built
from the root in the same isolated source tree, starting at `c2da12582c` and
then applying the crop patch. The normal checkout's build flags were unchanged.

| Case | Input bytes | Before ns/call | After ns/call | Speedup |
| --- | ---: | ---: | ---: | ---: |
| Empty | 0 | 15.9 | 20.2 | 0.79x |
| Short ASCII | 3 | 27.5 | 24.5 | 1.12x |
| ASCII title | 32 | 120.5 | 63.6 | 1.90x |
| ANSI title | 54 | 157.5 | 81.3 | 1.94x |
| ASCII panel | 3,320 | 7,541.2 | 3,640.1 | 2.07x |
| ANSI panel | 4,400 | 9,915.8 | 4,644.6 | 2.13x |
| ANSI panel with scroll offsets | 4,400 | 11,245.2 | 5,139.6 | 2.19x |
| Uncropped ASCII | 3,320 | 13,830.8 | 6,606.4 | 2.09x |
| UTF-8 panel | 4,160 | 7,361.1 | 4,661.9 | 1.58x |
| Dense ANSI | 1,640 | 3,317.4 | 2,225.4 | 1.49x |
| Long line | 1,048,576 | 865,990 | 82,520 | 10.49x |
| Large buffer, top 25 rows | 1,100,000 | 470,800 | 33,080 | 14.23x |
| Large buffer, bottom 25 rows | 1,100,000 | 1,525,310 | 175,390 | 8.70x |

The empty-input case regresses by 4.3 ns. The implementation removes ten lines
(90 to 80), uses `strlen`/`strchr` for sizing and skipped text, bypasses Unicode
width decoding for ASCII, and copies CSI sequences with `memcpy`. Height checks
run only when a newline advances the row. The allocation excludes skipped rows
and reserves reset sequences only for the requested height, with overflow checks.
For the bottom-25-rows case, the requested allocation falls from 1,140,001 to
2,851 bytes, calculated from the input length and reset counts. Each call still
uses one allocation. ANSI, UTF-8 and trailing-newline behavior are preserved.

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

## Assembler symbols and source splitting

Build radare2 from the root, then run:

```sh
make -C test/bench asm_code
test/bench/asm_code
```

The CSV reports microseconds. `equ` performs 4,096 substitutions with a fixed
referenced symbol and 0–8,192 unrelated symbols. Table construction and a
correctness check precede timing; the timed loop includes substitution and
freeing the result. Increasing unrelated symbols should not multiply lookup
cost. `lines` assembles 4,096–65,536 `.byte` directives and validates the emitted
bytes. Source generation is outside timing; assembly includes the normal
passes, tokenization, directives and output allocation, without a CPU backend.
These workloads isolate two generic libr/asm costs and need no ROM fixture.

Use identical compiler flags and repeat measurements when comparing versions.
For a real cartridge, separately time rasm2 with preprocessing, architecture
encoding and binary output enabled, and compare every result to the reference.
Remove the benchmark executable with `make -C test/bench clean-asm-code`.

## Analysis layouts and block storage

See [anal-layout.md](anal-layout.md) for the `anal-layout`, `anal-bb-storage`
and `anal-bb-lookup` benchmarks, their measurement boundaries, the pointer/pool/
inline matrix, and recorded CSV results.
