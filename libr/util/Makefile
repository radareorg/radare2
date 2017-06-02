include ../config.mk

NAME=r_util
CFLAGS+=-DCORELIB -I$(TOP)/shlr
DEPS=

OBJS=mem.o pool.o unum.o str.o hex.o file.o range.o tinyrange.o
OBJS+=prof.o cache.o sys.o buf.o w32-sys.o ubase64.o base85.o base91.o
OBJS+=list.o flist.o mixed.o btree.o chmod.o graph.o
OBJS+=regex/regcomp.o regex/regerror.o regex/regexec.o uleb128.o
OBJS+=sandbox.o calc.o thread.o thread_lock.o thread_msg.o
OBJS+=strpool.o bitmap.o p_date.o p_format.o print.o
OBJS+=p_seven.o slist.o randomart.o log.o zip.o debruijn.o
OBJS+=utf8.o strbuf.o lib.o name.o spaces.o signal.o syscmd.o
OBJS+=diff.o bdiff.o stack.o queue.o tree.o des.o idpool.o
OBJS+=punycode.o r_pkcs7.o r_x509.o r_asn1.o json_indent.o skiplist.o
OBJS+=r_json.o

# DO NOT BUILD r_big api (not yet used and its buggy)
ifeq (1,0)
ifeq (${HAVE_LIB_GMP},1)
  OBJS+=big-gmp.o
else
  ifeq (${HAVE_LIB_SSL},1)
    OBJS+=big-ssl.o
  else
    OBJS+=big.o
  endif
endif
endif

include $(SHLR)/zip/deps.mk

LDFLAGS+=${BN_LIBS}
LDFLAGS+=${TH_LIBS}
LDFLAGS+=${DL_LIBS}

# NetBSD 7.0 ships with backtrace(3) in -lexecinfo
ifeq (${BUILD_OS},netbsd)
ifneq ($(shell expr "`uname -r`" : '[0-6]\.'), 2)
  LDFLAGS+=-lexecinfo
endif
endif

EXTRA_PRE+=sdb_version
EXTRA_PRE+=spp_config

include ../rules.mk
include sdb.mk
include spp.mk

sync-regex regex-sync:
	-rm -rf src/
	cvs -qd anoncvs@anoncvs.ca.openbsd.org:/cvs get -P src/lib/libc/regex
	cp src/lib/libc/regex/* regex
