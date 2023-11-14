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
QJS_CFLAGS+=-D CONFIG_STACK_CHECK=y
QJS_CFLAGS+=-D QJS_NOABORT=1
QJS_CFLAGS+=-U CONFIG_BIGNUM
QJS_CFLAGS+=-U DUMP_LEAKS
QJS_CFLAGS+=-U NDEBUG

QJS_LIBS+=-lr_core -lr_config -lr_cons

QJS_VERSION=$(shell cat src/VERSION.txt)

JS_CFILES:=js_repl.c js_r2papi.c js_require.c

all: src $(JS_CFILES)

node_modules:
	mkdir -p node_modules
	npm i

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

NM=node_modules

js_r2papi.c:
#	npm i js_r2papi
	printf "Using r2papi version: "
	-jq .version node_modules/r2papi/package.json
	mkdir -p $(NM)

	cat	\
		$(NM)/r2papi/r2papi.js \
		$(NM)/r2papi/r2pipe.js \
		$(NM)/r2papi/base64.js \
		$(NM)/r2papi/ai.js \
		$(NM)/r2papi/shell.js \
		$(NM)/r2papi/esil.js \
		> $(NM)/r2papi/entrypoint.js
	sed \
		-e 's,exports,G,g' \
		-e 's,require(,G;//,g' \
		< $(NM)/r2papi/entrypoint.js \
		| grep -v 'use strict' \
		| grep -v 'r2pipe\.js' \
		> js_r2papi.qjs
	echo 'const r2pipe_js_1 = G;' >> js_r2papi.qjs
	npx minify --help > /dev/null npm i minify
	npx minify --js < js_r2papi.qjs > js_r2papi.mini.qjs
	npx uglify-js --help > /dev/null || npm i uglify-js
	npx uglify-js --no-annotations --toplevel --validate -c < js_r2papi.mini.qjs > js_r2papi.tiny.qjs
	@ls -l js_r2papi.qjs
	@ls -l js_r2papi.mini.qjs
	@ls -l js_r2papi.tiny.qjs
	echo 'static const char *const js_r2papi_qjs = "" \\' > js_r2papi.c
	r2 -fqcpcc js_r2papi.mini.qjs | grep -v ^const >> js_r2papi.c
# r2 -fqcpcc js_r2papi.tiny.qjs | grep -v ^const >> js_r2papi.c
	rm -f js_r2papi.mini.qjs js_r2papi.tiny.qjs

js_require.c:
	npx minify --help > /dev/null npm i minify
	npx minify --js < js_require.qjs > mini.qjs
	echo "`du -hs js_require.qjs|awk '{print $$1}'` => `du -hs mini.qjs|awk '{print $$1}'`"
	# 20K uglify
	npx uglify-js --help > /dev/null || npm i uglify-js
	npx uglify-js --no-annotations --toplevel --validate -c < mini.qjs > tiny.qjs
	@ls -l mini.qjs
	@ls -l tiny.qjs
	echo "`du -hs mini.qjs|awk '{print $$1}'` => `du -hs tiny.qjs|awk '{print $$1}'`"
	npx minify --help > /dev/null npm i minify
	npx minify --js < tiny.qjs > mini.qjs
	echo "`du -hs tiny.qjs|awk '{print $$1}'` => `du -hs mini.qjs|awk '{print $$1}'`"
	echo 'static const char *const js_require_qjs = "" \\' > js_require.c
	r2 -fqcpcc mini.qjs | grep -v ^const >> js_require.c

js_repl.c:
	# goto this s
	# 19K https://www.toptal.com/developers/javascript-minifier
	# ??K
	npx minify --help > /dev/null npm i minify
	npx minify --js < js_repl.qjs > mini.qjs
	echo "`du -hs js_repl.qjs|awk '{print $$1}'` => `du -hs mini.qjs|awk '{print $$1}'`"
	# 20K uglify
	npx uglify-js --help > /dev/null || npm i uglify-js
	npx uglify-js --no-annotations --toplevel --validate -c < mini.qjs > tiny.qjs
	@ls -l mini.qjs
	@ls -l tiny.qjs
	echo "`du -hs mini.qjs|awk '{print $$1}'` => `du -hs tiny.qjs|awk '{print $$1}'`"
	npx minify --help > /dev/null npm i minify
	npx minify --js < tiny.qjs > mini.qjs
	echo "`du -hs tiny.qjs|awk '{print $$1}'` => `du -hs mini.qjs|awk '{print $$1}'`"
	echo 'static const char *const js_repl_qjs = "" \\' > js_repl.c
	r2 -fqcpcc mini.qjs | grep -v ^const >> js_repl.c

lang_qjs.${EXT_SO}: src js_repl.c js_require.c
	# $(MAKE) CFLAGS_OPT="-Oz -DCONFIG_VERSION=\\\"0.1\\\"" -C $(QJS_NAME) libquickjs.a
#-Wl,-exported_symbols_list,symbols.lst
	-$(CC) -flto -D 'CONFIG_VERSION="$(VERSION)"' -g -Oz -Wl,-dead_strip -std=c99 $(DUK_CFLAGS) -I quickjs $(QJS_CFLAGS) $(CFLAGS) -fPIC $(LDFLAGS_LIB) \
		-o lang_qjs.$(EXT_SO) $(QJS_FILES) $(QJS_LIBS) qjs.c

$(QJS_NAME):
	git clone $(QJS_GITURL) $(QJS_NAME)

o:
	make clean && make && make user-install
