all: supported.langs ruby perl python lua

supported.langs:
	sh check-langs.sh

# TODO: make it less spaguetti
perl:
	@-[ "`grep perl supported.langs`" ] && cd perl && make

python:
	@-[ "`grep python supported.langs`" ] && cd python && make

ruby:
	@-[ "`grep ruby supported.langs`" ] && cd ruby && make

lua:
	@-[ "`grep lua supported.langs`" ] && cd lua && make

test:
	cd perl && make test
	cd python && make test
	cd ruby && make test
	cd lua && make test

install-python:
	@if [ "`grep python supported.langs`" ]; then \
	for a in python2.5 python2.6; do \
	mkdir -p ${DESTDIR}${PREFIX}/lib/$$a/r2 ; \
	touch ${DESTDIR}${PREFIX}/lib/$$a/r2/__init__.py ; \
	echo "Installing $$a r2 modules..." ; \
	cp -rf python/* ${DESTDIR}${PREFIX}/lib/$$a/r2 ; \
	cp -rf python/*libr* ${DESTDIR}${PREFIX}/lib/$$a/ ; \
	done ; \
	fi

install-lua:
	@echo TODO: install-lua

install-ruby:
	@if [ "`grep ruby supported.langs`" ]; then \
	for a in 1.8 1.9.1; do \
	mkdir -p ${DESTDIR}${PREFIX}/lib/ruby/$$a/r2 ; \
	echo "Installing ruby$$a r2 modules..." ; \
	cp -rf ruby/* ${DESTDIR}${PREFIX}/lib/ruby/$$a/r2 ; \
	cp -rf ruby/*libr* ${DESTDIR}${PREFIX}/lib/ruby/$$a ; \
	done ; \
	fi

install-perl:
	@if [ "`grep perl supported.langs`" ]; then \
	target=${DESTDIR}`perl -e 'print $$INC[0]'` ; \
	mkdir -p $$target/r2 ; \
	echo "Installing perl r2 modules..." ; \
	cp -rf perl/*.so $$target/ ; \
	cp -rf perl/*.pm $$target/r2 ; \
	cp -rf perl/*libr* $$target/r2 ; \
	fi

install: install-python install-ruby install-perl

oldtest:
	sh do-swig.sh r_bp
	python test.py

clean:
	cd python && make clean
	cd perl && make clean
	cd ruby && make clean
	cd lua && make clean

.PHONY: ruby lua python perl clean oldtest test all
