r2=$(shell git log|head -n1|awk '{print $$2}')
CNT=$(shell cat tmp/radare2-$(r2)/count.txt 2> /dev/null || git log|grep ^commit|wc -l | awk '{print $$1}')
TMP=$(shell pwd)/tmp
PREFIX=$(TMP)/prefix

all:
	@echo "Usage: make [action] [option=value]"
	@echo "make r2        # run r2"
	@echo "make use r2=x  # run r2"
	@echo "make ls        # list installed versions of r2"
	@echo "make lsa       # list all/available versions of r2"
	@echo "make lsa       # list all/available versions of r2"

r2:
	tmp/prefix/bin/radare2 -v

use: $(TMP)/radare2
	if [ ! -d tmp/radare2-$(r2) ]; then git clone tmp/radare2 tmp/radare2-$(r2) && cd tmp/radare2-$(r2) && git reset --hard $(r2) ; fi
	if [ -d tmp/radare2-$(r2) ]; then cd tmp/radare2-$(r2) && git log |head -n9 ; fi
	r2pm -r $(MAKE) -C tmp/radare2-$(r2) -j
	$(MAKE) -C tmp/radare2-$(r2) symstall

$(TMP)/radare2:
	git clone https://github.com/radareorg/radare2 $(TMP)/radare2

ls:
	@cd tmp && ls | grep radare2- |cut -d - -f 2

lsa:
	@cd tmp/radare2 && git log |grep ^commit | awk '{print $$2}'

html:
	r2 -i index.r2.js -- > index.html

run:
	mkdir -p logs
	r2r -o logs/$(CNT)-$(r2).json -i ../db/perf
	cd logs && r2 -qi ../main.r2.js --

.PHONY: all ls lsa html run use r2

