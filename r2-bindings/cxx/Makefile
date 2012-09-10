LANG=cxx
LANG_EXT=cxx
LIBS_PFX=
PREFIX?=/usr

all: mkcxx

include ../rules.mk

LIBS=r_lib.so
#LIBS=r_search.so r_util.so
LIBS=r_core.so r_asm.so
#LIBS=r_util.so

mkcxx:
	@echo c++ bindings has been disabled

mkcxx_real:
	for a in ${LIBS} ; do \
		mod=`echo $$a|cut -d . -f 1` ; \
		valabind --cxx -N Radare -m $$mod --vapidir=../vapi $$mod && \
		${CXX} -shared -fPIC -o $$a $${mod}.cxx `pkg-config --cflags --libs $$mod` ; \
	done

mrproper:
	rm -f *.cxx
