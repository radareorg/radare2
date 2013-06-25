LANG=lua
LANG_EXT=lua
LIBS_PFX=

MY_SOEXT=so
include ../rules.mk

tri:
	valaswig -o r_debug.i -m r_debug --vapidir ../../libr/vapi/ r_debug
	swig -lua -I/usr/include/libr r_debug.i
	gcc r_debug_wrap.c -shared -fPIC -I /usr/include/libr -I /usr/include/lua5.1/ -o _r_debug.so -lr_debug -lr_bp -lr_reg -lr_util

bis:
	valaswig-cc -NRadare lua r_io -I../../libr/include r_io `pkg-config --libs r_io`
