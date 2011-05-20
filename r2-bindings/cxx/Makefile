LANG=cxx
LANG_EXT=cxx
LIBS_PFX=
PREFIX?=/usr

all: mkcxx

include ../rules.mk

LIBS=r_lib.so
#LIBS=r_search.so r_util.so
LIBS=r_asm.so
#LIBS=r_util.so

mkcxx:
	for a in ${LIBS} ; do \
		mod=`echo $$a|cut -d . -f 1` ; \
		valabind --cxx -m $$mod --vapidir=../vapi $$mod && \
		${CXX} -shared -fPIC -o $$a $${mod}.cxx `pkg-config --cflags --libs $$mod` ; \
	done

mrproper:
	rm -f *.cxx
