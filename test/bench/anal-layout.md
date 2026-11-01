# Analysis layout experiments

## Current revision: aligned vectors and deferred construction sorting

The 2026-11-01 revision restores the unchanged `R_ALIGNED(16)` vector header.
Both function vectors are adjacent, at offsets 16 (`bbs`) and 48 (`vars`).
On x86-64 the function is 272 bytes, aligned to 16, versus master's 288 bytes
and the previous PR's 256-byte, 8-aligned layout. The block remains 232 bytes
versus master's 248. The older measurements below used natural vector header
alignment and do not describe the final layout or its memory consumption.

Unsorted exact lookup uses the existing global block tree and verifies function
membership. Removal scans an unsorted vector without reordering it, and uses
binary search when address order is already cached. Relocation only invalidates
order in every owner. Overlapping lookups retain insertion order while building.
The individual block-walk entry point no longer sorts; the complete function
analysis sorts after its plugin callback. Ordered presentation requests address
order itself. DOT graphs and incoming-block lists therefore remain deterministic
after later block edits. `afbs`/`afbsa` reuse the order flag; other explicit sorts
are preserved through exact lookup and restored at an ordered presentation.

The rerun compares master `f8a584ff62b1`, the previous PR rebased onto that
same master, and the aligned analysis tree at `5f85ed10a927` with identical
`-O2` flags. The published rebased commits have the exact trees used for the
local timing builds; both local and published identities are in the environment
metadata. Real-world cases have one warmup
and three measured fresh processes, with fixed-seed randomized variant order.
The lookup benchmark now accepts a fourth argument `lookup` to interleave an
exact lookup after every insertion, exposing repeated sorting during construction.

To reproduce, prepare installed `ROOT/baseline`, `ROOT/previous`, and
`ROOT/radare2` checkouts, each configured with
`./configure --prefix="$PWD/_install" CFLAGS=-O2`, built from the root and
installed with `make install`. Provide the same fixtures at
`ROOT/radare2/test/bins`. Run:

```
python3 ROOT/radare2/test/bench/anal-aligned.py ROOT
```

The driver compiles the three C benchmarks against each matching installation,
runs real-world analysis, lookup (including interleaved lookup), and the complete
pointer/pool/inline storage matrix. Results, individual runs, compiler/commit
metadata and checksums are saved to `ROOT/results`. Linux live-heap reporting is
unavailable in the C driver (`heap_in_use=0`); allocator subtotals and RSS are
reported separately. Whole-process wall time includes loading and accounting.

Validation for the aligned revision: root build and installation, lint and
`git diff --check` pass. All five focused unit binaries (`test_vec`,
`test_anal_block`, `test_anal_function`, `test_anal_var`, `test_io`) pass.
Selected analysis/graph/decompiler/project regressions give 700 OK, two known
broken cases, 11 skips and zero failures. The function test covers unsorted
exact/overlapping lookup, foreign-block rejection, relocation across shared
owners, explicit order preservation, sorted and unsorted removal, and restoration
at the ordered boundary.

### Rerun results, 2026-11-01

Ubuntu 24.04 x86-64, GCC 13.3, identical `-O2` builds; one warmup and three
measured processes per real-world case. The previous PR was rebased onto
the same master before measuring. CPU is the complete analysis command;
process wall time also includes loading and accounting. Medians:

| Case | Command | Master CPU s | Previous PR CPU s | Aligned PR CPU s | vs master | vs previous PR |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| ls | aaa | 0.355941 | 0.367804 | 0.337398 | -5.21% | -8.27% |
| pigz | aaa | 0.828053 | 0.763155 | 0.772904 | -6.66% | +1.28% |
| libc | aaa | 9.224596 | 9.272366 | 8.853804 | -4.02% | -4.51% |
| Mastodon | aaa | 46.252496 | 45.938586 | 45.408457 | -1.82% | -1.15% |
| ls | aaaa | 0.339302 | 0.342243 | 0.339476 | +0.05% | -0.81% |
| pigz | aaaa | 0.798971 | 0.806653 | 0.769496 | -3.69% | -4.61% |

CPU samples vary; inspect the min/max ranges and individual runs before
attributing small changes to alignment or sorting alone. These are Linux
measurements; the historical macOS numbers below were not rerun here.

| aaa case | Master function-owned B | Previous PR B | Aligned PR B | vs master | Master peak RSS B | Aligned peak RSS B |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| ls | 807,120 | 707,696 | 760,400 | -5.79% | 36,499,456 | 36,491,264 |
| pigz | 1,234,136 | 1,067,176 | 1,150,216 | -6.80% | 42,012,672 | 41,869,312 |
| libc | 19,311,448 | 17,155,912 | 18,510,888 | -4.15% | 144,789,504 | 142,774,272 |
| Mastodon | 101,248,416 | 87,704,144 | 94,331,040 | -6.83% | 354,373,632 | 345,985,024 |

Fresh function-owned storage is 768 B/eight allocations on master,
304 B/two allocations in the previous unaligned PR, and 320 B/two
allocations in this aligned revision, on this Linux allocator. Including
the initial eight-pointer reservation gives 840/376/392 B respectively.
Blocks and shared state are excluded. Alignment increases other embedded
RVec headers as well, including variable-owned vectors; the old memory
totals therefore cannot be reused.

| 8,192 blocks, insertion order | Lookup after each append | Master ns/append | Previous PR ns/append | Aligned PR ns/append |
| --- | --- | ---: | ---: | ---: |
| asc | no | 57.399 | 55.827 | 59.089 |
| desc | no | 89.277 | 37.635 | 41.774 |
| shuffle | no | 195.407 | 205.692 | 220.130 |
| asc | yes | 118.048 | 84.882 | 90.979 |
| desc | yes | 115.234 | 85231.603 | 157.977 |
| shuffle | yes | 272.661 | 77397.315 | 293.254 |

The interleaved timer includes the lookup after each append. Final sorted
lookup and sorting preparation are separate columns in the full CSV.
The baseline foreign-function lookup bug is recorded, not treated as
equivalent behavior; both PR revisions reject the foreign block.

The full storage matrix contains 864 fresh processes: three revisions ×
three storage modes × four initial capacities × eight lengths × three
runs. It remains a container experiment, not an inline analysis engine.
The lookup matrix has 270 processes, and real analysis has 72 including
warmups. Every real-world case preserves function/block/membership counts
and the block checksum across all revisions. Pointer ownership remains
necessary for shared blocks and stable intrusive-tree identity.

Raw data and medians/ranges:

- [Real-world results](anal-aligned-realworld-results.csv) and [72 runs](anal-aligned-realworld-runs.csv).
- [Lookup results](anal-aligned-lookup-results.csv) and [270 runs](anal-aligned-lookup-runs.csv).
- [Storage results](anal-aligned-storage-results.csv) and [864 runs](anal-aligned-storage-runs.csv).
- [Compiler, commit identities and fixture revision](anal-aligned-environment.json).

## Historical experiments

Build the checkout with `./configure --prefix="$PWD/_install" CFLAGS=-O2`,
`make -j8` and `make install`. Run `make -C test/bench anal-layout anal-bb-storage`.
Keep separate installed libraries and executable/header builds for the baseline
and candidate. Select each build's libraries with `DYLD_LIBRARY_PATH` on macOS
or `LD_LIBRARY_PATH` on Linux. Set `R2_NOPLUGINS=1` to exclude user plugins.

```
test/bench/anal-layout test/bins/elf/ls aaa
test/bench/anal-layout test/bins/mach0/Mastodon aaa
test/bench/anal-bb-storage ptr 9 8
test/bench/anal-bb-storage pool 9 8
test/bench/anal-bb-storage inline 9 8
```

`anal-layout` reports actual allocator sizes and allocation counts for each
function, its strings, diff, import list, variable objects and vector buffers,
and all three hash tables including buckets and owned keys/values. Shared
analysis state and blocks are excluded from that subtotal. Unique block object
allocations have a separate subtotal; their owned state is included only in the
whole-process live heap/RSS figures. Fresh-function bytes exclude shared state.
The one-block estimate adds the normal eight-pointer reservation and excludes
the block itself. The repeated walk calls `r_anal_function_realsize` and reports
CPU nanoseconds per block membership. The block checksum covers addresses,
sizes, jumps and fails, independently of the memory subtotals.

Allocator byte counts are available on macOS and Linux. Whole-process live heap
is available on macOS; unsupported byte counters report zero. Peak RSS is in
bytes. Counts include live allocations, not all allocations made during analysis.

`anal-bb-storage` compares synthetic containers with 4,096 functions: individual
block allocations (`ptr`), one fixed contiguous block allocation plus pointer
vectors (`pool`), and vectors containing blocks by value (`inline`). All modes
initialize and sum the same address, size, jump and fail fields, and check the
sum before timing. Each scan visits at least 30 million blocks. Construction and
free CPU times are separate. Storage bytes include vector headers, their spare
capacity and blocks; other function fields, block-owned state and shared-block
ownership are excluded. `allocations` counts initial allocation calls and
`growths` counts additional vector reallocations. Pooling is an idealized fixed
pool, without dynamic slab/free-slot bookkeeping. These are container timings,
not complete analysis speedups.

For each baseline/candidate build, run every combination of modes `ptr`, `pool`,
`inline`, initial capacities `1`, `2`, `4`, `8`, and lengths `1`, `2`, `8`, `9`,
`33`, `64`, `65`, `256`. The lengths just above powers of two expose capacity
slack. Randomize order and report medians of at least three fresh processes.
Keep the per-run data to inspect variation. Initial capacity is an experiment;
this patch retains the normal vector growth policy.

An inline vector cannot replace the production block-pointer vector directly:
blocks belong to the analysis tree, can have multiple function owners, and
survive through references outside their owner's vector. Reallocation, removal
and sorting of by-value elements would invalidate those pointers and intrusive
tree links. A production pool needs stable addresses or a separate handle-based
redesign, plus tests for deletion, splitting, merging and shared blocks.

## Recorded experiment, 2026-10-30

macOS arm64, Apple Clang 21, `-O2`; baseline `766503ab572a` already includes
the block-pointer vector. The storage matrix has 192 combinations, with three
process runs each. Medians and min/max CPU times are in
[anal-bb-storage-results.csv](anal-bb-storage-results.csv); all 576 individual
runs are in [anal-bb-storage-runs.csv](anal-bb-storage-runs.csv).

| Layout-only experiment | arm64/x86-64 function | arm64/x86-64 block | i386 function | i386 block |
| --- | ---: | ---: | ---: | ---: |
| Baseline | 288 | 248 | 224 | 164 |
| Natural vector headers | 264 | 248 | 184 | 164 |
| Also reorder the block fields | 264 | 232 | 184 | 164 |
| Also move stack_pop out of meta (implemented) | 256 | 232 | 184 | 164 |
| Pack the eight booleans instead (rejected) | 256 | 232 | 176 | 164 |

Sizes are bytes. The arm64 result also uses the actual headers; the x86-64 and
i386 checks use Clang freestanding layout probes extracted from the declarations,
with target-sized pointers and size_t, the current RBNode and R_REF_TYPE shapes,
and no system headers. They are not cross-architecture runtime tests.

The implemented change keeps boolean field access and fits stack_pop into
existing function padding while reducing the nested metadata from 40 to 32
bytes on 64-bit targets. Function alignment falls from 16 to 8 and the block
vector moves from offset 192 to 16. The CPU follow-up keeps `_max_end` at offset 32 and
block addr/size/jump/fail at 40/48/56/64. These are offsets within the object; allocations are not guaranteed
to start on a cache-line boundary.

On this allocator, function objects cross from the 320-byte to the 256-byte
class. Block objects stay in the 256-byte class despite the layout improvement.
A fresh function, including owned state but excluding shared state and blocks,
falls from 784 bytes/eight allocations to 288 bytes/two allocations. With the
first eight-pointer backing store this is 848 to 352 bytes. The remaining
eager allocation is its 32-byte diff object. Empty label and instruction-variable
tables now cost zero allocations; lookups and label output support absence.

Inline storage is sensitive to capacity slack: in the candidate layout, a
one-block inline vector reserved for eight blocks uses 2,072 bytes per synthetic
function versus 344 for individual pointers and 320 for a fixed pool. Reserving
one slot gives 280, 296 and 272 bytes respectively. Nine blocks use 4,120 bytes
inline, 2,456 with individual pointers, and 2,240 with a fixed pool. These figures
include synthetic vector headers and block objects, but exclude all other
function fields and block-owned allocations. See the CSVs for every capacity,
length, layout, allocation count, construction/free time and scan time.

Keep the pointer representation for this patch. A segmented per-analysis pool
is a possible follow-up to reduce allocation cost while preserving addresses,
but the idealized pool does not consistently improve scan time in this matrix.
A compact by-value graph snapshot can be useful for read-only graph operations
without moving the authoritative blocks. A single optional function extension
for pin, fingerprint/size, diff and imports gives a 224-byte function in a
layout-only probe; its allocation, absent-state semantics and indirection still
need an implementation and measurements. No cold split or flag packing is
included in the production change.

## Ordered block lookup

The function vector caches increasing address order. Construction appends
without pointer shifts, invalidating the order flag on an out-of-order append.
Analysis restores order after the block walk and plugin callback; indexed
operations and ordered presentation restore it on demand. Exact lookups and removals use the vector's sorted-search
helpers; out-of-range exact queries stop before searching. Containing-block
queries retain the existing augmented global interval tree, which can handle
overlapping blocks. Their linear fallback now follows address order and stops
when a block starts above the query. Sorting by address alone does not make a
single predecessor sufficient for overlapping ranges.

The `afbs` commands can still explicitly request other orderings. They invalidate
an order flag, so the next indexed operation restores address order once. The
flag uses existing padding. Relocation restores order in every owner of a shared
block. Repeated address sorts in graph, disassembly, signatures, diffing and type
analysis now use the same helper.

`anal-bb-lookup` times just membership insertion after constructing the blocks,
then 200,000 exact hits and 200,000 misses. It keeps another 32,768 unrelated
blocks in the global index. Run each build for lengths `1`, `8`, `64`, `1024`,
`8192` and insertion orders `asc`, `desc`, `shuffle`, with three fresh processes
per case. The shuffle is a fixed permutation. Construction of the global tree
and unrelated function is outside the insertion timer.

```
make -C test/bench anal-bb-lookup
test/bench/anal-bb-lookup 8192 asc
test/bench/anal-bb-lookup 8192 desc
test/bench/anal-bb-lookup 8192 shuffle
```

All 90 runs are in [anal-bb-lookup-runs.csv](anal-bb-lookup-runs.csv), with
medians/ranges in [anal-bb-lookup-results.csv](anal-bb-lookup-results.csv).
`foreign_match=true` records the baseline bug where the global exact lookup
returns a block that is absent from the requested function; the candidate
rejects it. Ordered insertion still moves pointers for out-of-order arrivals:
the strict-order experiment records that worst-case cost in
[anal-bb-lookup-strict-results.csv](anal-bb-lookup-strict-results.csv). The shipped
append-and-sort policy avoids it, and the final benchmark times preparation
separately from insertion and lookup. It batches at least 4,096 insertions so
small-function construction times are not dominated by timer resolution.

## Historical full analysis results (first PR revision)
Three measured runs after a warmup for each phase. `baseline` is the merged
block-vector commit; `compact` applies layout/lazy allocation only; `strict`
keeps the vector sorted at each insertion; `cached` is the final policy. The
complete data and min/max values are in [anal-analysis-results.csv](anal-analysis-results.csv),
with all warmup and measured runs in [anal-analysis-runs.csv](anal-analysis-runs.csv).

| Sample | Function-owned bytes before / after | Live heap bytes before / after | Peak RSS bytes before / after | aaa CPU s before / after |
| --- | ---: | ---: | ---: | ---: |
| ls | 752,192 / 671,056 | 9,848,256 / 9,706,944 | 24,821,760 / 24,412,160 | 0.320 / 0.327 |
| pigz | 1,155,888 / 1,017,600 | 13,658,256 / 13,443,392 | 33,112,064 / 33,619,968 | 0.834 / 0.862 |
| libc | 17,896,960 / 16,352,896 | 92,000,000 / 89,480,432 | 130,809,856 / 130,433,024 | 9.435 / 9.983 |
| Mastodon | 95,671,248 / 82,386,144 | 284,839,184 / 271,498,784 | 323,371,008 / 294,453,248 | 39.484 / 40.795 |

Function-owned memory falls 10.8%, 12.0%, 8.6% and 13.9% respectively.
The first PR revision's CPU medians are 2.2–5.8% higher, with overlapping run ranges; these
measurements do not establish a full-analysis speedup. This is a memory and
lookup improvement. Timings are environment-sensitive, so use the per-run
data rather than attributing the whole change to a single field rearrangement.

Every sample has identical function/block/membership counts and block checksums
across all phases. `aaa`/`aaaa` snapshots of ls and pigz preserve functions,
instructions, edges, xrefs and variables; some graph block arrays now appear
in address order. Decompiler labels and annotation offsets follow that order.


## Real-world CPU follow-up

These measurements precede the rebase onto master `6835c8e49768`.
The measured baseline is `766503ab572a`, the first PR is `f5ab97690cf9`,
and current analysis code is `2809bf3e6bb8` (also present in the rebased PR).
The rebase replays the same patches; the new master changes nine other files.
Do not interpret these as a post-rebase performance rerun.

All CPU values time the complete `aaa` or `aaaa` command, excluding file loading
and the later synthetic traversal. Each variant has one warmup and three measured
fresh processes, with fixed-seed randomized order. Values below are medians;
the CSVs contain every run and CPU ranges. Process wall time includes loading,
accounting and the traversal, so it is not analysis-only time.

Native macOS 27.0.1 arm64, Apple Clang 21, `-O2`, user plugins disabled:

| Case | Command | Baseline CPU s | First PR CPU s | Current CPU s | Change |
| --- | --- | ---: | ---: | ---: | ---: |
| ls | aaa | 0.323286 | 0.323492 | 0.308852 | -4.46% |
| pigz | aaa | 0.830408 | 0.856542 | 0.802765 | -3.33% |
| libc | aaa | 9.550234 | 9.737535 | 9.050020 | -5.24% |
| Mastodon | aaa | 39.703161 | 39.899789 | 38.937766 | -1.93% |
| ls | aaaa | 0.333862 | 0.331564 | 0.314871 | -5.69% |
| pigz | aaaa | 0.841628 | 0.869303 | 0.805143 | -4.34% |

CPU falls 1.9–5.7% across these six workloads. Function-owned memory falls
8.6–13.9%, while whole-process live heap falls 1.4–4.7%. Peak RSS is the median
of each process's high-water mark, not retained function storage.

| Case | Function-owned bytes before / after | Live heap bytes before / after | Peak RSS bytes before / after |
| --- | ---: | ---: | ---: |
| ls | 752,192 / 671,056 | 9,844,112 / 9,704,480 | 24,772,608 / 24,674,304 |
| pigz | 1,155,888 / 1,017,600 | 13,659,568 / 13,443,392 | 34,045,952 / 33,964,032 |
| libc | 17,896,960 / 16,352,896 | 92,024,240 / 89,495,424 | 131,186,688 / 129,236,992 |
| Mastodon | 95,671,248 / 82,386,144 | 284,836,496 / 271,515,664 | 324,468,736 / 308,051,968 |

[Native medians and ranges](anal-realworld-native-results.csv) and
[all 72 native runs](anal-realworld-native-runs.csv) include the first PR revision
alongside the original baseline and current implementation.

Ubuntu 24.04 x86-64, GCC 13.3, `-O2`, GitHub Actions runner:

| Case | Command | Baseline CPU s | Current CPU s | Change |
| --- | --- | ---: | ---: | ---: |
| ls | aaa | 0.227612 | 0.224544 | -1.35% |
| pigz | aaa | 0.536372 | 0.546943 | 1.97% |
| libc | aaa | 6.306872 | 6.318451 | 0.18% |
| Mastodon | aaa | 32.197054 | 31.969495 | -0.71% |
| ls | aaaa | 0.234070 | 0.232023 | -0.87% |
| pigz | aaaa | 0.548703 | 0.554813 | 1.11% |

Linux is mixed: ls and Mastodon improve slightly; pigz's median is 1.1–2.0%
higher and libc is nearly unchanged. The pigz/libc ranges overlap. These data
do not establish a universal CPU improvement. Linux function-owned allocations
fall 11.2–13.5% for the four `aaa` cases; live-heap reporting is unavailable on
Linux in this driver. RSS and allocator subtotals are in
[Linux medians and ranges](anal-realworld-linux-results.csv), with
[all 48 runs](anal-realworld-linux-runs.csv).
The [Linux job](https://github.com/radareorg/radare2/actions/runs/41113283906)
passed the five unit binaries and selected analysis/graph/decompiler/IO suites.
Its fixture revision is `ed967a566eb7ef982fab23ef74b226af7ef9a003`.

A sampler during full Swift/Mastodon analysis found 2,497 of 3,846 samples in
lseek. The follow-up avoids an unused current-position query when descriptor
pcache reads are disabled. The cache-enabled path still captures the position;
no new cache or state is added. Balanced block-tree range queries now recurse
without allocating temporary vector stacks and preserve their callback order.
The tree augmentation stays beside address/size. These changes remove 41 more
production lines, making the full production diff 52 lines smaller.

The [tree-only predecessor runs](anal-realworld-tree-only-runs.csv) record the
interrupted 22-process experiment before the unused-seek fix. They do not form a
complete paired sample and are excluded from the current CPU claims.

Real block distributions explain why by-value storage is problematic:

| Case | Functions | One-block functions | Unique blocks | Function block memberships | Pointer-vector capacity |
| --- | ---: | ---: | ---: | ---: | ---: |
| ls | 145 | 18 | 3,319 | 3,319 | 5,456 |
| pigz | 222 | 116 | 4,645 | 4,645 | 7,272 |
| libc | 2,370 | 427 | 60,848 | 60,854 | 91,952 |
| Mastodon | 19,551 | 14,635 | 53,774 | 54,300 | 181,896 |

Swift has 526 more memberships than unique block objects, and glibc has six.
Also, 74.9% of Swift functions contain one block, while total pointer capacity
is 3.35 times the membership count. Replicating this spare capacity with full
232-byte objects is expensive. Authoritative blocks need stable identity in
multiple owners, the intrusive tree and external references. The pointer/inline
storage matrix above is a container experiment from the first PR layout; its
allocation totals remain applicable, while its scan timings reflect that layout.
No complete inline analysis implementation is claimed.

Validation before rebase: all five TinyCC jobs pass; full regression run:
9,389 OK, 22 known broken, 0 failures, 60 skipped, 2 unexpected fixes.
The updated native graph/Java/emulation/x86/IO selection gives 282 OK,
2 known broken and 0 failures. IO/cache unit checks, root build, lint and
`git diff --check` pass. Fresh ls/pigz `aaa` and `aaaa` snapshots preserve
functions, instructions, graph edges, xrefs and variables after normalizing
block-array order. Every completed timed case preserves function/block/
membership counts and the block checksum across variants.

To repeat the CI experiment, prepare checkouts at `ROOT/candidate` and
`ROOT/baseline`, and radare2-testbins at `ROOT/fixtures`, then run:

```
python3 ROOT/candidate/test/bench/anal-realworld-ci.py ROOT
```

It builds both with identical `-O2` flags, installs into separate prefixes,
runs the regression selections, alternates the real analyses and emits raw
JSON/CSV plus medians/ranges into `ROOT/results`. The temporary PR-only workflow
is removed from the final change; the experiment driver remains reproducible.
