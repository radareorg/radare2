all: supported.langs ruby perl python

supported.langs:
	sh check-langs.sh

# TODO: make it less spaguetti
perl:
	@-[ "`grep perl supported.langs`" ] && cd perl && make

python:
	@-[ "`grep python supported.langs`" ] && cd python && make

ruby:
	@-[ "`grep ruby supported.langs`" ] && cd ruby && make

test:
	cd perl && make test
	cd python && make test
	cd ruby && make test

install-python:
	@if [ "`grep python supported.langs`" ]; then \
	for a in python2.5 python2.6; do \
	mkdir -p /usr/lib/$$a/r2 ; \
	touch /usr/lib/$$a/r2/__init__.py ; \
	echo "Installing $$a r2 modules..." ; \
	cp -rf python/* /usr/lib/$$a/r2 ; \
	cp -rf python/*libr* /usr/lib/$$a/ ; \
	done ; \
	fi

install-ruby:
	@if [ "`grep ruby supported.langs`" ]; then \
	for a in 1.8 1.9.1; do \
	mkdir -p /usr/lib/ruby/$$a/r2 ; \
	echo "Installing ruby$$a r2 modules..." ; \
	cp -rf ruby/* /usr/lib/ruby/$$a/r2 ; \
	cp -rf ruby/*libr* /usr/lib/ruby/$$a ; \
	done ; \
	fi

install-perl:
	@echo "Installing perl r2 modules... NOT YET IMPLEMENTED"
	@if [ "`grep perl supported.langs`" ]; then \
	target=`perl -e 'print $$INC[0]'` ; \
	mkdir -p $$target/r2 ; \
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

.PHONY: ruby python perl clean oldtest test all
