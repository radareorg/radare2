

r2?=$(shell cat tmp/prefix/commit.txt 2> /dev/null || (cd tmp/radare2 && git log|head -n1|awk '{print $$2}'))
CNT=$(shell cat tmp/prefix/count.txt 2> /dev/null || (cd tmp/radare2 && git log|grep ^commit|wc -l | awk '{print $$1}'))
TMP=$(shell pwd)/tmp
PREFIX=$(TMP)/prefix

all: lint
	@echo "Usage: make [action] [option=value]"
	@echo "make r2             # get version of current r2"
	@echo "make use r2=x       # build and install new r2 ($(r2))"
	@echo "make ls             # list installed versions of r2"
	@echo "make lsa            # list all/available versions of r2"
	@echo "make lsa            # list all/available versions of r2"
	@echo "make run            # run benchmarks testsuite with current r2"
	@echo "make html           # generate index.html"
	@echo "make world count=10 # build the last 10 commits from r2"
	@echo "make force-world    # like 'world', but ignores if logs are generated"

lint:
ifeq ($(r2),)
	echo Error r2 cant be empty ; exit 1
endif
ifeq ($(CNT),)
	echo Error CNT cant be empty ; exit 1
endif

r2:
	tmp/prefix/bin/radare2 -v

use: $(TMP)/radare2 lint
	echo "Using $(r2)"
	if [ ! -d tmp/radare2-$(r2) ]; then git clone tmp/radare2 tmp/radare2-$(r2) && cd tmp/radare2-$(r2) && git reset --hard $(r2) ; fi
	if [ -d tmp/radare2-$(r2) ]; then cd tmp/radare2-$(r2) && git log |head -n9  ; \
		echo $(r2) > $(TMP)/radare2-$(r2)/commit.txt ; \
		git log|grep ^commit|wc -l | awk '{print $$1}' > ../radare2-$(r2)/count.txt ; fi
	export CFLAGS=-Ofast && cd tmp/radare2-$(r2) && \
		r2pm -r -- ./configure --with-syscapstone --prefix=$(PREFIX) --without-dylink --with-checks-level=0 > $(TMP)/radare2-$(r2)/configure.log 2>&1 && \
		time r2pm -r $(MAKE) -j > $(TMP)/radare2-$(r2)/build.log 2>&1
	$(MAKE) -C tmp/radare2-$(r2) symstall > $(TMP)/radare2-$(r2)/install.log 2>&1
	cp -f tmp/radare2-$(r2)/count.txt tmp/prefix/count.txt
	cp -f tmp/radare2-$(r2)/commit.txt tmp/prefix/commit.txt

$(TMP)/radare2:
	git clone https://github.com/radareorg/radare2 $(TMP)/radare2

count=20
world:
	for a in `make lsa|head -n $(count)` ; do if [ -d tmp/radare2-$$a ]; then continue ; fi ; echo $$a ; sleep 1 ; make use r2=$$a ; make run r2=$$a ;  done

force-world:
	for a in `make lsa|head -n $(count)` ; do echo $$a ; sleep 1 ; make use r2=$$a ; make run r2=$$a ;  done

ls:
	@cd tmp && ls | grep radare2- |cut -d - -f 2

lsa: $(TMP)/radare2
	@cd tmp/radare2 && git log |grep ^commit | awk '{print $$2}'

html:
	$(MAKE) main > index.html
	open index.html
# r2 -qi main.r2.js -- > index.html

run:
	mkdir -p logs
	PATH=$(TMP)/prefix/bin/:${PATH} r2r -o logs/$(CNT)-$(r2)-1.json -i ../db/perf
	PATH=$(TMP)/prefix/bin/:${PATH} r2r -o logs/$(CNT)-$(r2)-2.json -i ../db/perf
	PATH=$(TMP)/prefix/bin/:${PATH} r2r -o logs/$(CNT)-$(r2)-3.json -i ../db/perf
	$(MAKE) main

main:
	@cd logs && r2 -qi ../main.r2.js --

.PHONY: all ls lsa html run use r2

