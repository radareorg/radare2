# libFuzzer radare2 tests

## Setup

Get libFuzzer-capable clang

```shell
make setup
```

Running with the provided Makefile

```shell
cd test/fuzz
make setup
make build
make run-fuzzer TARGET=fuzz_types_parser
```

## Help

```shell
make usage
```

```shell
make help TARGET=fuzz_r_run_parseline
```

## Corpus

Corpus files are taken from `./test/fuzz/corpus/${TARGET}`.

* Copy the files you like in there before the `run-fuzzer`

**Note:** The `make build` command builds radare2 normally first, then builds the fuzzing targets with proper sanitizers and fuzzer support. This approach avoids the sanitizer linking issues that can occur when building the entire project with sanitizers enabled.


## Links

Refer to https://llvm.org/docs/LibFuzzer.html

**Run fuzzer**

```shell
make run-fuzzer TARGET=fuzz_r_run_parseline
```

**Run with custom options**

Note that `-detect_leaks=0` is always necessary in `FUZZER_OPTS`

```shell
make run-fuzzer TARGET=fuzz_r_run_parseline FUZZER_OPTS="-workers=1 -runs=50000 -timeout=3"
```

**Replay crashes**

```shell
make replay TARGET=fuzz_r_run_parseline CRASH_FILES="crash-*"
```

### Manual execution

**Show help**

```
./build/test/fuzz/fuzz_r_run_parseline -help=1
```

**Run fuzzer**

```
mkdir corpus_parseline
./build/test/fuzz/fuzz_r_run_parseline \
  -workers=1 -runs=50000 -timeout=3    \
  corpus_parseline
```

**Replay crashes**

```
./build/test/fuzz/fuzz_r_run_parseline crash-*
```

## Adding a new target

- add your test to /test/fuzz/meson.build
- add `/test/fuzz/fuzz_<name>.c` file
  - add system setup to `LLVMFuzzerInitialize` (disable logging, enable sandbox, etc)
  - add fuzz target to `LLVMFuzzerTestOneInput`
  - make sure input is short (ideally no longer than 256 bytes)
  - make sure no memory leaks are present
- `-close_fd_mask=2` (mute stderr) if your target is spammy
- `-ignore_ooms` `-fork=16` if you're likely to OOM
