# libFuzzer tests

## Setup

Get libFuzzer-capable clang

```shell
# Linux
export CC=clang-14
# macOS
export CC="$(brew --prefix llvm@14)/bin/clang"
```

Clean project

```shell
git clean -xdf
rm -rf shlr/capstone
rm -rf build
```

Build project with libFuzzer and sanitizers

```shell
# If you want to debug crashes
export CFLAGS="-g"
# Build project with test/fuzz
python3 ./sys/meson.py --fuzz --sanitize address,leak,fuzzer-no-link
```

## Run

Refer to https://llvm.org/docs/LibFuzzer.html

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
