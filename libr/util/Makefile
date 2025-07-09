include ../config.mk

NAME=r_util
CFLAGS+=-DR2_PLUGIN_INCORE -I$(TOP)/shlr
PCLIBS=@LIBZIP@ @DL_LIBS@
OBJS=mem.o unum.o str.o hex.o file.o range.o charset.o xdg.o rxml.o rlz4.o
OBJS+=prof.o sys.o buf.o sys_w32.o ubase64.o base85.o base91.o base36.o str_pseudo.o
OBJS+=list.o chmod.o graph.o event.o alloc.o donut.o print_code.o format2.o
OBJS+=regex/regcomp.o regex/regerror.o regex/regexec.o uleb128.o rstr.o str_strip.o
OBJS+=sandbox.o math.o thread.o thread_sem.o thread_lock.o thread_cond.o thread_chan.o
OBJS+=strpool.o bitmap.o time.o format.o pie.o print.o utype.o w32.o w32dw.o
OBJS+=seven.o randomart.o zip.o debruijn.o log.o getopt.o table.o sys_sh.o
OBJS+=utf8.o utf16.o utf32.o strbuf.o lib.o name.o spaces.o signal.o syscmd.o
OBJS+=udiff.o bdiff.o stack.o queue.o tree.o idpool.o assert.o bplist.o treemap.o
OBJS+=punycode.o pkcs7.o x509.o asn1.o asn1_str.o json_parser.o json_indent.o skiplist.o
OBJS+=pj.o rbtree.o intervaltree.o qrcode.o vector.o str_constpool.o str_trim.o
OBJS+=chartable.o protobuf.o graph_drawable.o axml.o sstext.o new_rbtree.o token.o
OBJS+=rvc.o rvc_git.o rvc_rvc.o bscanf.o rprintf.o base32.o bloom.o mmap.o

ifeq (${HAVE_GPERF},1)
OBJS+=d/ascii.o
OBJS+=d/ascii_oem.o
OBJS+=d/ascii_ansi.o
OBJS+=d/arabic_iso.o
OBJS+=d/arabic_windows.o
OBJS+=d/iso_646.o
OBJS+=d/cyrillic_iso.o
OBJS+=d/cyrillic_windows.o
OBJS+=d/greek_iso.o
OBJS+=d/greek_windows.o
OBJS+=d/hebrew_iso.o
OBJS+=d/hebrew_windows.o
OBJS+=d/macintosh.o
OBJS+=d/big5.o
OBJS+=d/pokered.o
OBJS+=d/katakana.o
OBJS+=d/hiragana.o
OBJS+=d/ebcdic37.o
OBJS+=d/iso8859_1.o
endif

ifeq ($(USE_SYSLZ4),1)
CFLAGS+=${LZ4_CFLAGS}
PCLIBS+=@LZ4_LDFLAGS@
LDFLAGS+=${LZ4_LDFLAGS}
else
CFLAGS+=-DUSE_RLZ4
endif

OBJS+=big_gmp.o
OBJS+=big_ssl.o
OBJS+=big.o

CWD=$(shell pwd)

LDFLAGS+=${BN_LIBS}
LDFLAGS+=${TH_LIBS}
LDFLAGS+=${DL_LIBS}

EXTRA_PRE+=spp_config
EXTRA_PRE+=charsets
#EXTRA_TARGETS=$(EXTRA_PRE)
EXTRA_CLEAN=doclean

myall: all

include ../rules.mk
include deps.mk
include sdb.mk
include spp.mk

f fast:
	rm -f sasa.c ; cat $(shell ls *.c| grep -v buf_| grep -v sasa) > sasa.c
	$(CC_LIB) $(LIBNAME) $(CFLAGS) sasa.c $(SHARED_OBJ) $(LINK) $(LDFLAGS)
	rm -f sasa.c

charsets:
	$(MAKE) -C d

doclean:
	$(MAKE) -C d clean

sync-regex regex-sync:
	-rm -rf src/
	cvs -qd anoncvs@anoncvs.ca.openbsd.org:/cvs get -P src/lib/libc/regex
	cp src/lib/libc/regex/* regex

.PHONY: charsets doclean sync-regex regex-sync
