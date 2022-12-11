include deps.mk

ifeq ($(QJS_BRANCH),frida)
	QJS_NAME=quickjs-frida
	QJS_GITURL=https://github.com/frida/quickjs
	QJS_CFLAGS+=-DQJS_NAME="\\"$(QJS_NAME)\\""
	QJS_CFLAGS+=-DQJS_FRIDA=1
else
	QJS_NAME=quickjs-bellard
	QJS_GITURL=https://github.com/bellard/quickjs
	QJS_CFLAGS+=-DQJS_NAME="\\"$(QJS_NAME)\\""
	QJS_CFLAGS+=-DQJS_FRIDA=0
endif

.PHONY: $(QJS_NAME)

QJS_CFLAGS+=-D QJS_LIBC=$(QJS_LIBC)
QJS_CFLAGS+=-U CONFIG_BIGNUM
QJS_CFLAGS+=-U DUMP_LEAKS
QJS_CFLAGS+=-U NDEBUG

QJS_LIBS+=-lr_core -lr_config -lr_cons

QJS_VERSION=$(shell cat src/VERSION.txt)

src:
	$(MAKE) $(QJS_NAME)
	rm -rf src
	mv $(QJS_NAME) src
	rm -rf src/.git
	mkdir -p src2
	ls src
	cp $(QJS_FILES) src/*.h src/Makefile src/VERSION.txt src2/
	rm -rf src
	mv src2 src
	sed -i -e 's/CONFIG_VERSION/"$(QJS_VERSION)"/' src/quickjs.c
	git add src

repl.c:
	# goto this s
	# 19K https://www.toptal.com/developers/javascript-minifier
	# ??K
	npx minify --help > /dev/null npm i minify
	npx minify --js < repl.qjs > mini.qjs
	echo "`du -hs repl.qjs|awk '{print $$1}'` => `du -hs mini.qjs|awk '{print $$1}'`"
	# 20K uglify
	npx uglify-js --help > /dev/null || npm i uglify-js
	npx uglify-js --no-annotations --toplevel --validate -c < mini.qjs > tiny.qjs
	@ls -l mini.qjs
	@ls -l tiny.qjs
	echo "`du -hs mini.qjs|awk '{print $$1}'` => `du -hs tiny.qjs|awk '{print $$1}'`"
	npx minify --help > /dev/null npm i minify
	npx minify --js < tiny.qjs > mini.qjs
	echo "`du -hs tiny.qjs|awk '{print $$1}'` => `du -hs mini.qjs|awk '{print $$1}'`"
	# echo 'const char *const repl_qjs = {' > repl.c
	echo 'const char *const repl_qjs = "" \\' > repl.c
	r2 -fqcpcc mini.qjs | grep -v ^const >> repl.c

lang_qjs.${EXT_SO}: src repl.c
	# $(MAKE) CFLAGS_OPT="-Oz -DCONFIG_VERSION=\\\"0.1\\\"" -C $(QJS_NAME) libquickjs.a
#-Wl,-exported_symbols_list,symbols.lst
	-$(CC) -flto -D 'CONFIG_VERSION="$(VERSION)"' -g -Oz -Wl,-dead_strip -std=c99 $(DUK_CFLAGS) -I quickjs $(QJS_CFLAGS) $(CFLAGS) -fPIC $(LDFLAGS_LIB) \
		-o lang_qjs.$(EXT_SO) $(QJS_FILES) $(QJS_LIBS) qjs.c

$(QJS_NAME):
	git clone $(QJS_GITURL) $(QJS_NAME)

o:
	make clean && make && make user-install
