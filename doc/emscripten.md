Building for the browser
========================

# Install emscripten:

    git clone git://github.com/kripken/emscripten.git
    export PATH=/path/to/emscripten:$PATH
    make clean


# Build radare

    sys/emscripten.sh


<!--

--- random notes ---

export CC="emcc --ignore-dynamic-linking"
./configure --prefix=/usr --disable-shared --enable-static --disable-debugger --with-compiler=emscripten --without-pic --with-nonpic
emmake make -j4 

cd binr/radare2
 emcc ../../libr/*/*.o radare2.c -I ../../libr/include/ -DR2_BIRTH=\"pop\" -DR2_GITTIP=\"123\" ../../libr/db/sdb/src/*.o

binr/rax2/rax2.js:

emcc -O2 rax2.o ../../libr/util/libr_util.a -o rax2.js

binr/rasm2/rasm2.js:

emcc -O2  -L.. -o rasm2.js   ../../shlr/sdb/src/libsdb.a ../../libr/fs/p/grub/libgrubfs.a -lm $A/util/libr_util.a $A/asm/libr_asm.a rasm2.o ../../libr/util/libr_util.a  ../../libr/parse/libr_parse.a  ../../libr/db/libr_db.a ../../libr/syscall/libr_syscall.a  ../../libr/asm/libr_asm.a  ../../libr/lib/libr_lib.a ../../libr/db/libr_db.a ../../shlr/sdb/src/libsdb.a ../../libr/util/libr_util.a

-->
