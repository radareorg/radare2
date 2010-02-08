LANG=python
LANG_EXT=py
LIBS_PFX=_

include ../rules.mk

tri:
	valaswig -o r_debug.i -m r_debug --vapidir ../../libr/vapi/ r_debug
	swig -python -I/usr/include/libr r_debug.i
	gcc r_debug_wrap.c -shared -fPIC -I /usr/include/libr -I /usr/include/python2.6/ -o _r_debug.so -lr_debug -lr_bp -lr_reg -lr_util

bis:
	valaswig-cc python r_io -I../../libr/include r_io `pkg-config --libs r_io`

bin:
	swig -python -c++ -o r_bin.cpp -Wall -DR_API -I../../libr/include r_bin.i.experimental
	g++ -shared -fPIC -I../../libr/include -I/usr/include/python2.5 -lr_bin -lr_util -o _r_bin.so r_bin.cpp
