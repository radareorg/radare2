r2?=master
# r2?=$(shell cat tmp/prefix/commit.txt 2> /dev/null || (cd tmp/radare2 2> /dev/null ; git log|head -n1|awk '{print $$2}'))
CNT=$(shell cat tmp/radare2-$(r2)/count.txt 2> /dev/null || (cd tmp/radare2 2> /dev/null ; git log|grep ^commit|wc -l | awk '{print $$1}'))
TMP=$(shell pwd)/tmp
PREFIX=$(TMP)/prefix
SO_EXT=$(shell r2 -H R2_LIBEXT)
DB=$(shell pwd)/../db

SOME=master
SOME+=5.8.8
SOME+=5.8.6
SOME+=5.8.4
SOME+=5.8.2
SOME+=5.8.0
SOME+=5.7.8
SOME+=5.7.6
SOME+=5.7.4
SOME+=5.7.2
SOME+=5.7.0

all: lint mem.$(SO_EXT)
	@echo "Usage: make [action] [option=value]"
	@echo "make r2             # get version of current r2"
	@echo "make use r2=x       # build and install new r2 ($(r2))"
	@echo "make ls             # list installed versions of r2"
	@echo "make lsa            # list all/available versions of r2"
	@echo "make lsa            # list all/available versions of r2"
	@echo "make run            # run benchmarks testsuite with current r2"
	@echo "make mem            # run the memory profile/statistics"
	@echo "make html           # generate index.html"
	@echo "make world count=10 # build the last 10 commits from r2"
	@echo "make force-world    # like 'world', but ignores if logs are generated"
	@echo "make some           # run some tags only (master 5.8.8 5.8.6 ...)"

mem.$(SO_EXT):
	$(CC) -fPIC -dynamiclib mem.c -o mem.$(SO_EXT)
# $(CC) -arch x86_64 -arch arm64 -fPIC -shared mem.c -o mem.$(SO_EXT)

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
		r2pm -r -- meson b --prefix=$(PREFIX) -Dchecks_level=0 > $(TMP)/radare2-$(r2)/configure.log 2>&1 && \
		r2pm -r -- ninja -C b
	#sudo $(MAKE) -C tmp/radare2-$(r2) uninstall > /dev/null
	rm -rf tmp/prefix/bin tmp/prefix/lib
	cd tmp/radare2-$(r2) && \
		r2pm -r -- ninja -C b install > $(TMP)/radare2-$(r2)/install.log 2>&1
	cp -f tmp/radare2-$(r2)/count.txt tmp/prefix/count.txt
	cp -f tmp/radare2-$(r2)/commit.txt tmp/prefix/commit.txt

$(TMP)/radare2:
	git clone https://github.com/radareorg/radare2 $(TMP)/radare2

count=20
world:
	for a in `make lsa|head -n $(count)` ; do if [ -d tmp/radare2-$$a ]; then continue ; fi ; echo $$a ; sleep 1 ; make use r2=$$a ; make run r2=$$a ;  done

some:
	for a in ${SOME} ; do if [ -d tmp/radare2-$$a ]; then continue ; fi ; echo $$a ; sleep 1 ; make use r2=$$a ; make run r2=$$a ;  done

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
	-LD_LIBRARY_PATH=$(PREFIX)/lib/:$(PREFIX)/x86_64-linux-gnu/ \
	DYLD_LIBRARY_PATH=$(PREFIX)/lib PATH=$(PREFIX)/bin/:$${PATH} \
		r2r -o logs/$(CNT)-$(r2)-1.json $(DB)/perf
	-LD_LIBRARY_PATH=$(PREFIX)/lib/:$(PREFIX)/x86_64-linux-gnu/ \
	DYLD_LIBRARY_PATH=$(PREFIX)/lib PATH=$(PREFIX)/bin/:$${PATH} \
		r2r -o logs/$(CNT)-$(r2)-2.json $(DB)/perf
	-LD_LIBRARY_PATH=$(PREFIX)/lib/:$(PREFIX)/x86_64-linux-gnu/ \
	DYLD_LIBRARY_PATH=$(PREFIX)/lib PATH=$(PREFIX)/bin/:$${PATH} \
		r2r -o logs/$(CNT)-$(r2)-3.json $(DB)/perf
	-LD_LIBRARY_PATH=$(PREFIX)/lib/:$(PREFIX)/x86_64-linux-gnu/ \
	DYLD_LIBRARY_PATH=$(PREFIX)/lib PATH=$(PREFIX)/bin/:$${PATH} \
		r2 -v > logs/$(CNT)-$(r2).version
	$(MAKE) html

R2=$(PWD)/tmp/prefix/bin/radare2
mem:
	-R2=$(R2) R2_ARGS="r2 /bin/ls" \
	   frida -l mem.frida.js -f ${R2} 2> a.txt
	r2 -qi mem.r2.js -- > logs/$(CNT)-$(r2).memory
	cat logs/$(CNT)-$(r2).memory

main:
	@cd logs && r2 -qi ../main.r2.js --

.PHONY: all ls lsa html run use r2 mem

