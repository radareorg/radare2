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

install:
	# python install
	@if [ "`grep python supported.langs`" ]; then \
	for a in python2.5 python2.6; do \
	mkdir -p /usr/lib/$$a/r2 ; \
	touch /usr/lib/$$a/r2/__init__.py ; \
	echo "Installing $$a r2 modules..." ; \
	cp -rf python/* /usr/lib/$$a/r2 ; \
	cp -rf python/*libr* /usr/lib/$$a/ ; \
	done ; \
	fi

oldtest:
	sh do-swig.sh r_bp
	python test.py

clean:
	rm -rf python/*.so python/*.c python/*.i
	rm -rf perl/*.so perl/*.pm perl/*.c perl/*.i
	rm -rf ruby/*.so ruby/*.c ruby/*.i

.PHONY: ruby python perl clean oldtest test all
