all: ruby perl python

perl:
	cd perl && make

python:
	cd python && make

ruby:
	cd ruby && make

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

.PHONY: ruby python perl clean oldtest test all
