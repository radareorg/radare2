# Analysis layout experiments

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
vector moves from offset 192 to 16. Block addr/size/jump/fail move into offsets
32/40/48/56. These are offsets within the object; allocations are not guaranteed
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

## Full analysis results
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
The final CPU medians are 2.2–5.8% higher, with overlapping run ranges; these
measurements do not establish a full-analysis speedup. This is a memory and
lookup improvement. Timings are environment-sensitive, so use the per-run
data rather than attributing the whole change to a single field rearrangement.

Every sample has identical function/block/membership counts and block checksums
across all phases. `aaa`/`aaaa` snapshots of ls and pigz preserve functions,
instructions, edges, xrefs and variables; some graph block arrays now appear
in address order. Decompiler labels and annotation offsets follow that order.
