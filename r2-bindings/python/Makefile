LANG=python
LANG_EXT=py
LIBS_PFX=_
PREFIX?=/usr

include ../rules.mk

tri:
	valaswig -o r_debug.i -m r_debug --vapidir ../../libr/vapi/ r_debug
	swig -python -I/usr/include/libr r_debug.i
	$(CC) r_debug_wrap.c -shared -fPIC -I /usr/include/libr -I /usr/include/python2.6/ -o _r_debug.so -lr_debug -lr_bp -lr_reg -lr_util

mytest:
	mkdir -p r2
	cp r_bin.py* r2
	cp _r_bin* r2
	PYTHONPATH=. python test-r_bin.py

bis:
	valaswig-cc python r_io -I../../libr/include r_io `pkg-config --libs r_io`

mrproper:
	a=python`python --version 2>&1 | cut -d ' ' -f 2 | cut -d . -f 1,2`/site-packages ; \
	rm -rf ${PREFIX}/lib/$a/r2
