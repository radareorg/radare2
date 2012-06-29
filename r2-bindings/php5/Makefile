LANG=php5
LANG_EXT=php5
LIBS_PFX=

include ../rules.mk

tri:
	valaswig -N Radare -o r_debug.i -m r_debug --vapidir ../../libr/vapi/ r_debug
	swig -lua -I/usr/include/libr r_debug.i
	gcc r_debug_wrap.c -shared -fPIC -I /usr/include/libr -I /usr/include/lua5.1/ -o _r_debug.so -lr_debug -lr_bp -lr_reg -lr_util

bis:
	valaswig-cc -NRadare lua r_io -I../../libr/include r_io `pkg-config --libs r_io`
