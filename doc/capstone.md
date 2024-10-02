# Capstone

Capstone Engine is the disassembler engine used by radare2 by default for
some architectures.

R2 supports capstone 4 and 5.

* capstone3: legacy support (only available on Debian systems probably)
* capstone4: previous release, found in many distros, not recommended if you care about modern x86 or arm64 binaries
* capstone5: stable release (default)
* capstone6: (aka next) abi/api breaking, not supported yet (see the section below)

By default r2 will build statically against capstone5 (unless you specify
the --with-capstone4 or --with-syscapstone configure flags)

## Capstone6

Note that capstone6 is still under development (not yet released at the moment of writing this document), so APIs are changing frequently and there are so many changes in APIs and enums that will break support with all the previous versions of Capstone.

## Using System Capstone

You can link capstone dynamically (by using --with-syscapstone), this will skip all the download and build steps of capstone inside `shlr/capstone`.and just link against the version of capstone found in the system. That's what distros usually want.

**NOTE**: that building against capstone-master is cursedd, because cs-master reports v5, but code is from v4, so it fails to compile because of missing enums and archs.

## v4

To build r2 against capstone4 use the following oneliner:

```sh
sys/install.sh --with-capstone4
```

You can find other capstone flags

```sh
$ ./configure --help | grep capstone
  --without-capstone     dont build the capstone dependency
  --with-capstone-next   build next branch of the capstone disassembler
  --with-capstone5       build v5 branch of capstone5 (default)
  --with-capstone4       build v4 branch of capstone
  --with-syscapstone     force to use system-wide capstone
  --without-syscapstone  avoid the system-wide capstone
```
