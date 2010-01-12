all: r_bp.so r_asm.so r_diff.so r_debug.so r_hash.so r_cons.so r_core.so r_search.so r_db.so r_lib.so

r_bp.so:
	cd .. && sh do-swig.sh python r_bp

r_diff.so:
	cd .. && sh do-swig.sh python r_diff

r_asm.so:
	cd .. && sh do-swig.sh python r_asm

r_debug.so:
	cd .. && sh do-swig.sh python r_debug

r_hash.so:
	cd .. && sh do-swig.sh python r_hash

r_cons.so:
	cd .. && sh do-swig.sh python r_cons

# XXX r_reg is broken
r_reg.so:
	cd .. && sh do-swig.sh python r_reg

# XXX r_reg is broken
r_bin.so:
	cd .. && sh do-swig.sh python r_bin

r_core.so:
	cd .. && sh do-swig.sh python r_core

r_search.so:
	cd .. && sh do-swig.sh python r_search

r_db.so:
	cd .. && sh do-swig.sh python r_db

r_lib.so:
	cd .. && sh do-swig.sh python r_lib

test:
	python test-r_bp.py
	python test-r_asm.py

clean:
	rm -f *.so

.PHONY: all test clean
