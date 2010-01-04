MODS=r_bp r_util r_diff r_hash r_socket r_reg

all: python

test:
	sh do-test.sh

oldtest:
	sh do-swig.sh r_bp
	python test.py

clean:
	rm -rf python/*
	rm -rf perl/*

python:
	for a in ${MODS} ; do sh do-swig.sh python $$a ; done

perl:
	for a in ${MODS} ; do sh do-swig.sh perl $$a ; done

.PHONY: python perl clean oldtest test all
