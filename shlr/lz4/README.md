LZ4 - Library Files
================================

The `/lib` directory contains many files, but depending on project's objectives,
not all of them are necessary.

#### Minimal LZ4 build

The minimum required is **`lz4.c`** and **`lz4.h`**,
which provides the fast compression and decompression algorithm.
They generate and decode data using [LZ4 block format].


#### High Compression variant

For more compression ratio at the cost of compression speed,
the High Compression variant called **lz4hc** is available.
Add files **`lz4hc.c`** and **`lz4hc.h`**.
The variant still depends on regular `lib/lz4.*` source files.


#### Frame variant, for interoperability

In order to produce compressed data compatible with `lz4` command line utility,
it's necessary to encode lz4-compressed blocks using the [official interoperable frame format].
This format is generated and decoded automatically by the **lz4frame** library.
Its public API is described in `lib/lz4frame.h`.
In order to work properly, lz4frame needs all other modules present in `/lib`,
including, lz4 and lz4hc, and also **xxhash**.
So it's necessary to include all `*.c` and `*.h` files present in `/lib`.


#### Advanced / Experimental API

A complex API defined in `lz4frame_static.h` contains definitions
which are not guaranteed to remain stable in future versions.
As a consequence, it must be used with static linking ***only***.


#### Windows : using MinGW+MSYS to create DLL

DLL can be created using MinGW+MSYS with the `make liblz4` command.
This command creates `dll\liblz4.dll` and the import library `dll\liblz4.lib`.
The import library is only required with Visual C++.
The header files `lz4.h`, `lz4hc.h`, `lz4frame.h` and the dynamic library
`dll\liblz4.dll` are required to compile a project using gcc/MinGW.
The dynamic library has to be added to linking options.
It means that if a project that uses LZ4 consists of a single `test-dll.c`
file it should be linked with `dll\liblz4.dll`. For example:
```
    gcc $(CFLAGS) -Iinclude/ test-dll.c -o test-dll dll\liblz4.dll
```
The compiled executable will require LZ4 DLL which is available at `dll\liblz4.dll`.


#### Miscellaneous

Other files present in the directory are not source code. There are :

 - `LICENSE` : contains the BSD license text
 - `Makefile` : `make` script to compile and install lz4 library (static and dynamic)
 - `liblz4.pc.in` : for `pkg-config` (used in `make install`)
 - `README.md` : this file

[official interoperable frame format]: ../doc/lz4_Frame_format.md
[LZ4 block format]: ../doc/lz4_Block_format.md


#### License

All source material within __lib__ directory are BSD 2-Clause licensed.
See [LICENSE](LICENSE) for details.
The license is also reminded at the top of each source file.
