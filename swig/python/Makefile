LANG=python
LANG_EXT=py
LIBS_PFX=_
PREFIX?=/usr

include ../rules.mk

tri:
	valaswig -o r_debug.i -m r_debug --vapidir ../../libr/vapi/ r_debug
	swig -python -I/usr/include/libr r_debug.i
	gcc r_debug_wrap.c -shared -fPIC -I /usr/include/libr -I /usr/include/python2.6/ -o _r_debug.so -lr_debug -lr_bp -lr_reg -lr_util

bis:
	valaswig-cc python r_io -I../../libr/include r_io `pkg-config --libs r_io`

mrproper:
	rm -rf ${PREFIX}/lib/python2.5/r2
	rm -rf ${PREFIX}/lib/python2.5/site-packages/r2
	rm -rf ${PREFIX}/lib/python2.5/libr*
	rm -rf ${PREFIX}/lib/python2.5/_libr*
	rm -rf ${PREFIX}/lib/python2.5/site-packages/libr*
	rm -rf ${PREFIX}/lib/python2.5/site-packages/_libr*
	#
	rm -rf ${PREFIX}/lib/python2.6/r2
	rm -rf ${PREFIX}/lib/python2.6/site-packages/r2
	rm -rf ${PREFIX}/lib/python2.6/libr*
	rm -rf ${PREFIX}/lib/python2.6/_libr*
	rm -rf ${PREFIX}/lib/python2.6/site-packages/libr*
	rm -rf ${PREFIX}/lib/python2.6/site-packages/_libr*
