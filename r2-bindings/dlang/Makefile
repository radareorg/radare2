LANG=dlang
LANG_EXT=dlang
LIBS_PFX=
PREFIX?=/usr

all: mkdlang

include ../rules.mk

#LIBS=r_lib.so
#LIBS=r_search.so r_util.so
LIBS=r_core.so r_asm.so r_bin.so
#LIBS=r_util.so

mkdlang:
	@echo D bindings has been disabled

uh:
	dmd test_asm.d r_asm.d

mkdlang_real:
	for a in ${LIBS} ; do \
		mod=`echo $$a|cut -d . -f 1` ; \
		valabind --dlang -N Radare -m $$mod --vapidir=../vapi $$mod && \
		${CXX} -shared -fPIC -o $$a $${mod}.dlang `pkg-config --cflags --libs $$mod` ; \
	done

mrproper:
	rm -f *.dlang
