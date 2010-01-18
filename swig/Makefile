all: supported.langs ruby perl python

supported.langs:
	sh check-langs.sh

# TODO: make it less spaguetti
perl:
	@-[ "`grep perl supported.langs`" ] && cd perl && make

python:
	@-[ "`grep python supported.langs`" ] && cd python && make

ruby:
	@-[ "`grep python supported.langs`" ] && cd python && make

test:
	cd perl && make test
	cd python && make test
	cd ruby && make test

oldtest:
	sh do-swig.sh r_bp
	python test.py

clean:
	rm -rf python/*
	rm -rf perl/*
	rm -rf ruby/*

.PHONY: ruby python perl clean oldtest test all
