#
# QuickJS Javascript Engine
# 
# Copyright (c) 2017-2021 Fabrice Bellard
# Copyright (c) 2017-2021 Charlie Gordon
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

ifeq ($(shell uname -s),Darwin)
CONFIG_DARWIN=y
endif
# Windows cross compilation from Linux
#CONFIG_WIN32=y
# use link time optimization (smaller and faster executables but slower build)
CONFIG_LTO=y
# consider warnings as errors (for development)
#CONFIG_WERROR=y
# force 32 bit build for some utilities
#CONFIG_M32=y

ifdef CONFIG_DARWIN
# use clang instead of gcc
CONFIG_CLANG=y
CONFIG_DEFAULT_AR=y
endif

# installation directory
prefix=/usr/local

# use the gprof profiler
#CONFIG_PROFILE=y
# use address sanitizer
#CONFIG_ASAN=y
# include the code for BigInt/BigFloat/BigDecimal and math mode
CONFIG_BIGNUM=y

OBJDIR=.obj

ifdef CONFIG_WIN32
  ifdef CONFIG_M32
    CROSS_PREFIX=i686-w64-mingw32-
  else
    CROSS_PREFIX=x86_64-w64-mingw32-
  endif
  EXE=.exe
else
  CROSS_PREFIX=
  EXE=
endif
ifdef CONFIG_CLANG
  HOST_CC=clang
  CC=$(CROSS_PREFIX)clang
  CFLAGS=-g -Wall -MMD -MF $(OBJDIR)/$(@F).d
  CFLAGS += -Wextra
  CFLAGS += -Wno-sign-compare
  CFLAGS += -Wno-missing-field-initializers
  CFLAGS += -Wundef -Wuninitialized
  CFLAGS += -Wunused -Wno-unused-parameter
  CFLAGS += -Wwrite-strings
  CFLAGS += -Wchar-subscripts -funsigned-char
  CFLAGS += -MMD -MF $(OBJDIR)/$(@F).d
  ifdef CONFIG_DEFAULT_AR
    AR=$(CROSS_PREFIX)ar
  else
    ifdef CONFIG_LTO
      AR=$(CROSS_PREFIX)llvm-ar
    else
      AR=$(CROSS_PREFIX)ar
    endif
  endif
else
  HOST_CC=gcc
  CC=$(CROSS_PREFIX)gcc
  CFLAGS=-g -Wall -MMD -MF $(OBJDIR)/$(@F).d
  CFLAGS += -Wno-array-bounds -Wno-format-truncation
  ifdef CONFIG_LTO
    AR=$(CROSS_PREFIX)gcc-ar
  else
    AR=$(CROSS_PREFIX)ar
  endif
endif
STRIP=$(CROSS_PREFIX)strip
ifdef CONFIG_WERROR
CFLAGS+=-Werror
endif
DEFINES:=-D_GNU_SOURCE -DCONFIG_VERSION=\"$(shell cat VERSION.txt)\"
ifdef CONFIG_BIGNUM
DEFINES+=-DCONFIG_BIGNUM
endif
ifdef CONFIG_WIN32
DEFINES+=-D__USE_MINGW_ANSI_STDIO # for standard snprintf behavior
endif

CFLAGS+=$(DEFINES)
CFLAGS_DEBUG=$(CFLAGS) -O0
CFLAGS_SMALL=$(CFLAGS) -Os
CFLAGS_OPT=$(CFLAGS) -O2
CFLAGS_NOLTO:=$(CFLAGS_OPT)
LDFLAGS=-g
ifdef CONFIG_LTO
CFLAGS_SMALL+=-flto
CFLAGS_OPT+=-flto
LDFLAGS+=-flto
endif
ifdef CONFIG_PROFILE
CFLAGS+=-p
LDFLAGS+=-p
endif
ifdef CONFIG_ASAN
CFLAGS+=-fsanitize=address -fno-omit-frame-pointer
LDFLAGS+=-fsanitize=address -fno-omit-frame-pointer
endif
ifdef CONFIG_WIN32
LDEXPORT=
else
LDEXPORT=-rdynamic
endif

PROGS=qjs$(EXE) qjsc$(EXE) run-test262
ifneq ($(CROSS_PREFIX),)
QJSC_CC=gcc
QJSC=./host-qjsc
PROGS+=$(QJSC)
else
QJSC_CC=$(CC)
QJSC=./qjsc$(EXE)
endif
ifndef CONFIG_WIN32
PROGS+=qjscalc
endif
ifdef CONFIG_M32
PROGS+=qjs32 qjs32_s
endif
PROGS+=libquickjs.a
ifdef CONFIG_LTO
PROGS+=libquickjs.lto.a
endif

# examples
ifeq ($(CROSS_PREFIX),)
ifdef CONFIG_ASAN
PROGS+=
else
PROGS+=examples/hello examples/hello_module examples/test_fib
ifndef CONFIG_DARWIN
PROGS+=examples/fib.so examples/point.so
endif
endif
endif

all: $(OBJDIR) $(OBJDIR)/quickjs.check.o $(OBJDIR)/qjs.check.o $(PROGS)

QJS_LIB_OBJS=$(OBJDIR)/quickjs.o $(OBJDIR)/libregexp.o $(OBJDIR)/libunicode.o $(OBJDIR)/cutils.o $(OBJDIR)/quickjs-libc.o

QJS_OBJS=$(OBJDIR)/qjs.o $(OBJDIR)/repl.o $(QJS_LIB_OBJS)
ifdef CONFIG_BIGNUM
QJS_LIB_OBJS+=$(OBJDIR)/libbf.o 
QJS_OBJS+=$(OBJDIR)/qjscalc.o
endif

HOST_LIBS=-lm -ldl -lpthread
LIBS=-lm
ifndef CONFIG_WIN32
LIBS+=-ldl -lpthread
endif
LIBS+=$(EXTRA_LIBS)

$(OBJDIR):
	mkdir -p $(OBJDIR) $(OBJDIR)/examples $(OBJDIR)/tests

qjs$(EXE): $(QJS_OBJS)
	$(CC) $(LDFLAGS) $(LDEXPORT) -o $@ $^ $(LIBS)

qjs-debug$(EXE): $(patsubst %.o, %.debug.o, $(QJS_OBJS))
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

qjsc$(EXE): $(OBJDIR)/qjsc.o $(QJS_LIB_OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

ifneq ($(CROSS_PREFIX),)

$(QJSC): $(OBJDIR)/qjsc.host.o \
    $(patsubst %.o, %.host.o, $(QJS_LIB_OBJS))
	$(HOST_CC) $(LDFLAGS) -o $@ $^ $(HOST_LIBS)

endif #CROSS_PREFIX

QJSC_DEFINES:=-DCONFIG_CC=\"$(QJSC_CC)\" -DCONFIG_PREFIX=\"$(prefix)\"
ifdef CONFIG_LTO
QJSC_DEFINES+=-DCONFIG_LTO
endif
QJSC_HOST_DEFINES:=-DCONFIG_CC=\"$(HOST_CC)\" -DCONFIG_PREFIX=\"$(prefix)\"

$(OBJDIR)/qjsc.o: CFLAGS+=$(QJSC_DEFINES)
$(OBJDIR)/qjsc.host.o: CFLAGS+=$(QJSC_HOST_DEFINES)

qjs32: $(patsubst %.o, %.m32.o, $(QJS_OBJS))
	$(CC) -m32 $(LDFLAGS) $(LDEXPORT) -o $@ $^ $(LIBS)

qjs32_s: $(patsubst %.o, %.m32s.o, $(QJS_OBJS))
	$(CC) -m32 $(LDFLAGS) -o $@ $^ $(LIBS)
	@size $@

qjscalc: qjs
	ln -sf $< $@

ifdef CONFIG_LTO
LTOEXT=.lto
else
LTOEXT=
endif

libquickjs$(LTOEXT).a: $(QJS_LIB_OBJS)
	$(AR) rcs $@ $^

ifdef CONFIG_LTO
libquickjs.a: $(patsubst %.o, %.nolto.o, $(QJS_LIB_OBJS))
	$(AR) rcs $@ $^
endif # CONFIG_LTO

repl.c: $(QJSC) repl.js
	$(QJSC) -c -o $@ -m repl.js

qjscalc.c: $(QJSC) qjscalc.js
	$(QJSC) -fbignum -c -o $@ qjscalc.js

ifneq ($(wildcard unicode/UnicodeData.txt),)
$(OBJDIR)/libunicode.o $(OBJDIR)/libunicode.m32.o $(OBJDIR)/libunicode.m32s.o \
    $(OBJDIR)/libunicode.nolto.o: libunicode-table.h

libunicode-table.h: unicode_gen
	./unicode_gen unicode $@
endif

run-test262: $(OBJDIR)/run-test262.o $(QJS_LIB_OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

run-test262-debug: $(patsubst %.o, %.debug.o, $(OBJDIR)/run-test262.o $(QJS_LIB_OBJS))
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

run-test262-32: $(patsubst %.o, %.m32.o, $(OBJDIR)/run-test262.o $(QJS_LIB_OBJS))
	$(CC) -m32 $(LDFLAGS) -o $@ $^ $(LIBS)

# object suffix order: nolto, [m32|m32s]

$(OBJDIR)/%.o: %.c | $(OBJDIR)
	$(CC) $(CFLAGS_OPT) -c -o $@ $<

$(OBJDIR)/%.host.o: %.c | $(OBJDIR)
	$(HOST_CC) $(CFLAGS_OPT) -c -o $@ $<

$(OBJDIR)/%.pic.o: %.c | $(OBJDIR)
	$(CC) $(CFLAGS_OPT) -fPIC -DJS_SHARED_LIBRARY -c -o $@ $<

$(OBJDIR)/%.nolto.o: %.c | $(OBJDIR)
	$(CC) $(CFLAGS_NOLTO) -c -o $@ $<

$(OBJDIR)/%.m32.o: %.c | $(OBJDIR)
	$(CC) -m32 $(CFLAGS_OPT) -c -o $@ $<

$(OBJDIR)/%.m32s.o: %.c | $(OBJDIR)
	$(CC) -m32 $(CFLAGS_SMALL) -c -o $@ $<

$(OBJDIR)/%.debug.o: %.c | $(OBJDIR)
	$(CC) $(CFLAGS_DEBUG) -c -o $@ $<

$(OBJDIR)/%.check.o: %.c | $(OBJDIR)
	$(CC) $(CFLAGS) -DCONFIG_CHECK_JSVALUE -c -o $@ $<

regexp_test: libregexp.c libunicode.c cutils.c
	$(CC) $(LDFLAGS) $(CFLAGS) -DTEST -o $@ libregexp.c libunicode.c cutils.c $(LIBS)

unicode_gen: $(OBJDIR)/unicode_gen.host.o $(OBJDIR)/cutils.host.o libunicode.c unicode_gen_def.h
	$(HOST_CC) $(LDFLAGS) $(CFLAGS) -o $@ $(OBJDIR)/unicode_gen.host.o $(OBJDIR)/cutils.host.o

clean:
	rm -f repl.c qjscalc.c out.c
	rm -f *.a *.o *.d *~ unicode_gen regexp_test $(PROGS)
	rm -f hello.c test_fib.c
	rm -f examples/*.so tests/*.so
	rm -rf $(OBJDIR)/ *.dSYM/ qjs-debug
	rm -rf run-test262-debug run-test262-32

install: all
	mkdir -p "$(DESTDIR)$(prefix)/bin"
	$(STRIP) qjs qjsc
	install -m755 qjs qjsc "$(DESTDIR)$(prefix)/bin"
	ln -sf qjs "$(DESTDIR)$(prefix)/bin/qjscalc"
	mkdir -p "$(DESTDIR)$(prefix)/lib/quickjs"
	install -m644 libquickjs.a "$(DESTDIR)$(prefix)/lib/quickjs"
ifdef CONFIG_LTO
	install -m644 libquickjs.lto.a "$(DESTDIR)$(prefix)/lib/quickjs"
endif
	mkdir -p "$(DESTDIR)$(prefix)/include/quickjs"
	install -m644 quickjs.h quickjs-libc.h "$(DESTDIR)$(prefix)/include/quickjs"

###############################################################################
# examples

# example of static JS compilation
HELLO_SRCS=examples/hello.js
HELLO_OPTS=-fno-string-normalize -fno-map -fno-promise -fno-typedarray \
           -fno-typedarray -fno-regexp -fno-json -fno-eval -fno-proxy \
           -fno-date -fno-module-loader
ifdef CONFIG_BIGNUM
HELLO_OPTS+=-fno-bigint
endif

hello.c: $(QJSC) $(HELLO_SRCS)
	$(QJSC) -e $(HELLO_OPTS) -o $@ $(HELLO_SRCS)

ifdef CONFIG_M32
examples/hello: $(OBJDIR)/hello.m32s.o $(patsubst %.o, %.m32s.o, $(QJS_LIB_OBJS))
	$(CC) -m32 $(LDFLAGS) -o $@ $^ $(LIBS)
else
examples/hello: $(OBJDIR)/hello.o $(QJS_LIB_OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)
endif

# example of static JS compilation with modules
HELLO_MODULE_SRCS=examples/hello_module.js
HELLO_MODULE_OPTS=-fno-string-normalize -fno-map -fno-promise -fno-typedarray \
           -fno-typedarray -fno-regexp -fno-json -fno-eval -fno-proxy \
           -fno-date -m
examples/hello_module: $(QJSC) libquickjs$(LTOEXT).a $(HELLO_MODULE_SRCS)
	$(QJSC) $(HELLO_MODULE_OPTS) -o $@ $(HELLO_MODULE_SRCS)

# use of an external C module (static compilation)

test_fib.c: $(QJSC) examples/test_fib.js
	$(QJSC) -e -M examples/fib.so,fib -m -o $@ examples/test_fib.js

examples/test_fib: $(OBJDIR)/test_fib.o $(OBJDIR)/examples/fib.o libquickjs$(LTOEXT).a
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

examples/fib.so: $(OBJDIR)/examples/fib.pic.o
	$(CC) $(LDFLAGS) -shared -o $@ $^

examples/point.so: $(OBJDIR)/examples/point.pic.o
	$(CC) $(LDFLAGS) -shared -o $@ $^

###############################################################################
# documentation

DOCS=doc/quickjs.pdf doc/quickjs.html doc/jsbignum.pdf doc/jsbignum.html 

build_doc: $(DOCS)

clean_doc: 
	rm -f $(DOCS)

doc/%.pdf: doc/%.texi
	texi2pdf --clean -o $@ -q $<

doc/%.html.pre: doc/%.texi
	makeinfo --html --no-headers --no-split --number-sections -o $@ $<

doc/%.html: doc/%.html.pre
	sed -e 's|</style>|</style>\n<meta name="viewport" content="width=device-width, initial-scale=1.0">|' < $< > $@

###############################################################################
# tests

ifndef CONFIG_DARWIN
test: tests/bjson.so examples/point.so
endif
ifdef CONFIG_M32
test: qjs32
endif

test: qjs
	./qjs tests/test_closure.js
	./qjs tests/test_language.js
	./qjs tests/test_builtin.js
	./qjs tests/test_loop.js
	./qjs tests/test_std.js
	./qjs tests/test_worker.js
ifndef CONFIG_DARWIN
ifdef CONFIG_BIGNUM
	./qjs --bignum tests/test_bjson.js
else
	./qjs tests/test_bjson.js
endif
	./qjs examples/test_point.js
endif
ifdef CONFIG_BIGNUM
	./qjs --bignum tests/test_op_overloading.js
	./qjs --bignum tests/test_bignum.js
	./qjs --qjscalc tests/test_qjscalc.js
endif
ifdef CONFIG_M32
	./qjs32 tests/test_closure.js
	./qjs32 tests/test_language.js
	./qjs32 tests/test_builtin.js
	./qjs32 tests/test_loop.js
	./qjs32 tests/test_std.js
	./qjs32 tests/test_worker.js
ifdef CONFIG_BIGNUM
	./qjs32 --bignum tests/test_op_overloading.js
	./qjs32 --bignum tests/test_bignum.js
	./qjs32 --qjscalc tests/test_qjscalc.js
endif
endif

stats: qjs qjs32
	./qjs -qd
	./qjs32 -qd

microbench: qjs
	./qjs tests/microbench.js

microbench-32: qjs32
	./qjs32 tests/microbench.js

# ES5 tests (obsolete)
test2o: run-test262
	time ./run-test262 -m -c test262o.conf

test2o-32: run-test262-32
	time ./run-test262-32 -m -c test262o.conf

test2o-update: run-test262
	./run-test262 -u -c test262o.conf

# Test262 tests
test2-default: run-test262
	time ./run-test262 -m -c test262.conf

test2: run-test262
	time ./run-test262 -m -c test262.conf -a

test2-32: run-test262-32
	time ./run-test262-32 -m -c test262.conf -a

test2-update: run-test262
	./run-test262 -u -c test262.conf -a

test2-check: run-test262
	time ./run-test262 -m -c test262.conf -E -a

testall: all test microbench test2o test2

testall-32: all test-32 microbench-32 test2o-32 test2-32

testall-complete: testall testall-32

bench-v8: qjs
	make -C tests/bench-v8
	./qjs -d tests/bench-v8/combined.js

tests/bjson.so: $(OBJDIR)/tests/bjson.pic.o
	$(CC) $(LDFLAGS) -shared -o $@ $^ $(LIBS)

-include $(wildcard $(OBJDIR)/*.d)
