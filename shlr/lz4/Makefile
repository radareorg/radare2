# ################################################################
# LZ4 library - Makefile
# Copyright (C) Yann Collet 2011-2016
# All rights reserved.
#
# This Makefile is validated for Linux, macOS, *BSD, Hurd, Solaris, MSYS2 targets
#
# BSD license
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice, this
#   list of conditions and the following disclaimer in the documentation and/or
#   other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
# ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# You can contact the author at :
#  - LZ4 source repository : https://github.com/Cyan4973/lz4
#  - LZ4 forum froup : https://groups.google.com/forum/#!forum/lz4c
# ################################################################

# Version numbers
LIBVER_MAJOR_SCRIPT:=`sed -n '/define LZ4_VERSION_MAJOR/s/.*[[:blank:]]\([0-9][0-9]*\).*/\1/p' < ./lz4.h`
LIBVER_MINOR_SCRIPT:=`sed -n '/define LZ4_VERSION_MINOR/s/.*[[:blank:]]\([0-9][0-9]*\).*/\1/p' < ./lz4.h`
LIBVER_PATCH_SCRIPT:=`sed -n '/define LZ4_VERSION_RELEASE/s/.*[[:blank:]]\([0-9][0-9]*\).*/\1/p' < ./lz4.h`
LIBVER_SCRIPT:= $(LIBVER_MAJOR_SCRIPT).$(LIBVER_MINOR_SCRIPT).$(LIBVER_PATCH_SCRIPT)
LIBVER_MAJOR := $(shell echo $(LIBVER_MAJOR_SCRIPT))
LIBVER_MINOR := $(shell echo $(LIBVER_MINOR_SCRIPT))
LIBVER_PATCH := $(shell echo $(LIBVER_PATCH_SCRIPT))
LIBVER  := $(shell echo $(LIBVER_SCRIPT))

BUILD_STATIC:=yes

CPPFLAGS+= -DXXH_NAMESPACE=LZ4_
CFLAGS  ?= -O3
DEBUGFLAGS:= -Wall -Wextra -Wcast-qual -Wcast-align -Wshadow \
             -Wswitch-enum -Wdeclaration-after-statement -Wstrict-prototypes \
             -Wundef -Wpointer-arith -Wstrict-aliasing=1
CFLAGS  += $(DEBUGFLAGS) $(MOREFLAGS)
FLAGS    = $(CPPFLAGS) $(CFLAGS) $(LDFLAGS)

SRCFILES := $(sort $(wildcard *.c))


# OS X linker doesn't support -soname, and use different extension
# see : https://developer.apple.com/library/mac/documentation/DeveloperTools/Conceptual/DynamicLibraries/100-Articles/DynamicLibraryDesignGuidelines.html
ifeq ($(shell uname), Darwin)
	SHARED_EXT = dylib
	SHARED_EXT_MAJOR = $(LIBVER_MAJOR).$(SHARED_EXT)
	SHARED_EXT_VER = $(LIBVER).$(SHARED_EXT)
	SONAME_FLAGS = -install_name $(LIBDIR)/liblz4.$(SHARED_EXT_MAJOR) -compatibility_version $(LIBVER_MAJOR) -current_version $(LIBVER)
else
	SONAME_FLAGS = -Wl,-soname=liblz4.$(SHARED_EXT).$(LIBVER_MAJOR)
	SHARED_EXT = so
	SHARED_EXT_MAJOR = $(SHARED_EXT).$(LIBVER_MAJOR)
	SHARED_EXT_VER = $(SHARED_EXT).$(LIBVER)
endif

LIBLZ4 = liblz4.$(SHARED_EXT_VER)

.PHONY: default
default: lib-release

lib-release: DEBUGFLAGS :=
lib-release: lib

lib: liblz4.a liblz4

all: lib

all32: CFLAGS+=-m32
all32: all

liblz4.a: $(SRCFILES)
ifeq ($(BUILD_STATIC),yes)  # can be disabled on command line
	@echo compiling static library
	@$(CC) $(CPPFLAGS) $(CFLAGS) -c $^
	@$(AR) rcs $@ *.o
endif

$(LIBLZ4): $(SRCFILES)
	@echo compiling dynamic library $(LIBVER)
ifneq (,$(filter Windows%,$(OS)))
	@$(CC) $(FLAGS) -DLZ4_DLL_EXPORT=1 -shared $^ -o dll\$@.dll
	dlltool -D dll\liblz4.dll -d dll\liblz4.def -l dll\liblz4.lib
else
	@$(CC) $(FLAGS) -shared $^ -fPIC -fvisibility=hidden $(SONAME_FLAGS) -o $@
	@echo creating versioned links
	@ln -sf $@ liblz4.$(SHARED_EXT_MAJOR)
	@ln -sf $@ liblz4.$(SHARED_EXT)
endif

liblz4: $(LIBLZ4)

clean:
	@$(RM) core *.o liblz4.pc dll/liblz4.dll dll/liblz4.lib
	@$(RM) *.a *.$(SHARED_EXT) *.$(SHARED_EXT_MAJOR) *.$(SHARED_EXT_VER)
	@echo Cleaning library completed


#-----------------------------------------------------------------------------
# make install is validated only for Linux, OSX, BSD, Hurd and Solaris targets
#-----------------------------------------------------------------------------
ifneq (,$(filter $(shell uname),Linux Darwin GNU/kFreeBSD GNU OpenBSD FreeBSD NetBSD DragonFly SunOS))

DESTDIR     ?=
# directory variables : GNU conventions prefer lowercase
# see https://www.gnu.org/prep/standards/html_node/Makefile-Conventions.html
# support both lower and uppercase (BSD), use uppercase in script
prefix      ?= /usr/local
PREFIX      ?= $(prefix)
exec_prefix ?= $(PREFIX)
libdir      ?= $(exec_prefix)/lib
LIBDIR      ?= $(libdir)
includedir  ?= $(PREFIX)/include
INCLUDEDIR  ?= $(includedir)

ifneq (,$(filter $(shell uname),OpenBSD FreeBSD NetBSD DragonFly))
PKGCONFIGDIR ?= $(PREFIX)/libdata/pkgconfig
else
PKGCONFIGDIR ?= $(LIBDIR)/pkgconfig
endif

ifneq (,$(filter $(shell uname),SunOS))
INSTALL ?= ginstall
else
INSTALL ?= install
endif

INSTALL_PROGRAM ?= $(INSTALL)
INSTALL_DATA    ?= $(INSTALL) -m 644

liblz4.pc: liblz4.pc.in Makefile
	@echo creating pkgconfig
	@sed -e 's|@PREFIX@|$(PREFIX)|' \
         -e 's|@LIBDIR@|$(LIBDIR)|' \
         -e 's|@INCLUDEDIR@|$(INCLUDEDIR)|' \
         -e 's|@VERSION@|$(LIBVER)|' \
          $< >$@

install: lib liblz4.pc
	@$(INSTALL) -d -m 755 $(DESTDIR)$(PKGCONFIGDIR)/ $(DESTDIR)$(INCLUDEDIR)/ $(DESTDIR)$(LIBDIR)/
	@$(INSTALL_DATA) liblz4.pc $(DESTDIR)$(PKGCONFIGDIR)/
	@echo Installing libraries
ifeq ($(BUILD_STATIC),yes)
	@$(INSTALL_DATA) liblz4.a $(DESTDIR)$(LIBDIR)/liblz4.a
	@$(INSTALL_DATA) lz4frame_static.h $(DESTDIR)$(INCLUDEDIR)/lz4frame_static.h
endif
	@$(INSTALL_PROGRAM) liblz4.$(SHARED_EXT_VER) $(DESTDIR)$(LIBDIR)
	@ln -sf liblz4.$(SHARED_EXT_VER) $(DESTDIR)$(LIBDIR)/liblz4.$(SHARED_EXT_MAJOR)
	@ln -sf liblz4.$(SHARED_EXT_VER) $(DESTDIR)$(LIBDIR)/liblz4.$(SHARED_EXT)
	@echo Installing headers in $(INCLUDEDIR)
	@$(INSTALL_DATA) lz4.h $(DESTDIR)$(INCLUDEDIR)/lz4.h
	@$(INSTALL_DATA) lz4hc.h $(DESTDIR)$(INCLUDEDIR)/lz4hc.h
	@$(INSTALL_DATA) lz4frame.h $(DESTDIR)$(INCLUDEDIR)/lz4frame.h
	@echo lz4 libraries installed

uninstall:
	@$(RM) $(DESTDIR)$(LIBDIR)/pkgconfig/liblz4.pc
	@$(RM) $(DESTDIR)$(LIBDIR)/liblz4.$(SHARED_EXT)
	@$(RM) $(DESTDIR)$(LIBDIR)/liblz4.$(SHARED_EXT_MAJOR)
	@$(RM) $(DESTDIR)$(LIBDIR)/liblz4.$(SHARED_EXT_VER)
	@$(RM) $(DESTDIR)$(LIBDIR)/liblz4.a
	@$(RM) $(DESTDIR)$(INCLUDEDIR)/lz4.h
	@$(RM) $(DESTDIR)$(INCLUDEDIR)/lz4hc.h
	@$(RM) $(DESTDIR)$(INCLUDEDIR)/lz4frame.h
	@echo lz4 libraries successfully uninstalled

endif
