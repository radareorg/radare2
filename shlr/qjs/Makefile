include deps.mk


QJS_CFLAGS+=-D QJS_LIBC=$(QJS_LIBC)
QJS_CFLAGS+=-D QJS_NOABORT=1
QJS_CFLAGS+=-U DUMP_LEAKS
QJS_CFLAGS+=-D NDEBUG=1
# QJS_CFLAGS+=-U NDEBUG
QJS_CFLAGS+=-fvisibility=hidden

QJS_LIBS+=-lr_core -lr_config -lr_cons

JS_CFILES:=js_repl.c js_r2papi.c js_require.c

all: $(JS_CFILES)

# $(JS_CFILES): node_modules

node_modules:
	mkdir -p node_modules
	npm i

NM=node_modules

R2PAPI_FILES=
R2PAPI_FILES+=index.js
R2PAPI_FILES+=r2papi.js
R2PAPI_FILES+=r2pipe.js
R2PAPI_FILES+=base64.js
R2PAPI_FILES+=ai.js
R2PAPI_FILES+=r2frida.js
R2PAPI_FILES+=shell.js
R2PAPI_FILES+=esil.js
R2PAPI_FILES_JS=$(addprefix $(NM)/r2papi/,$(R2PAPI_FILES))

USE_CUSTOM_R2PAPI=1

js_r2papi.c: node_modules
ifeq ($(USE_CUSTOM_R2PAPI),1)
	cp /tmp/r2papi.r2.js js_r2papi.qjs
else
#	npm i js_r2papi
	printf "Using r2papi version: "
	-jq .version node_modules/r2papi/package.json
	mkdir -p $(NM)

	cat $(R2PAPI_FILES_JS) > $(NM)/r2papi/entrypoint.js
	echo 'var G={};' > js_r2papi.qjs
	sed \
		-e 's,exports,G,g' \
		-e 's,require(,G;//,g' \
		< $(NM)/r2papi/entrypoint.js \
		| grep -v 'use strict' \
		| grep -v 'r2pipe\.js' \
		>> js_r2papi.qjs
	echo 'const r2pipe_js_1 = G;' >> js_r2papi.qjs
endif
ifeq ($(USE_MINIFY),1)
	npx minify --help > /dev/null npm i minify
	npx minify --js < js_r2papi.qjs > js_r2papi.mini.qjs
else
	cp -f js_r2papi.qjs js_r2papi.mini.qjs
	# TODO remove multiline /* */ comments too
	cat js_r2papi.qjs | sed \
		-e 's,  *, ,g' \
		-e 's,\\/\\/.*/,,' \
		> js_r2papi.mini.qjs
endif
ifeq ($(USE_UGLIFY),1)
	npx uglify-js --help > /dev/null || npm i uglify-js
	npx uglify-js --no-annotations --toplevel --validate -c < js_r2papi.mini.qjs > js_r2papi.tiny.qjs
else
	cp -f js_r2papi.mini.qjs js_r2papi.tiny.qjs
endif
	@ls -l js_r2papi.qjs
	@ls -l js_r2papi.mini.qjs
	@ls -l js_r2papi.tiny.qjs
	echo 'static const char *const js_r2papi_qjs = "" \\' > js_r2papi.c
	r2 -fqcpcc js_r2papi.mini.qjs | grep -v ^const >> js_r2papi.c
# r2 -fqcpcc js_r2papi.tiny.qjs | grep -v ^const >> js_r2papi.c
#	rm -f js_r2papi.mini.qjs js_r2papi.tiny.qjs

js_require.c:
ifeq ($(USE_MINIFY),1)
	npx minify --help > /dev/null npm i minify
	npx minify --js < js_require.qjs > js_require.mini.qjs
else
	cp -f js_require.qjs js_require.mini.qjs
endif
	echo "`du -hs js_require.qjs|awk '{print $$1}'` => `du -hs js_require.mini.qjs|awk '{print $$1}'`"
ifeq ($(USE_UGLIFY),1)
	# 20K uglify
	npx uglify-js --help > /dev/null || npm i uglify-js
	npx uglify-js --no-annotations --toplevel --validate -c < js_require.mini.qjs > js_require.tiny.qjs
else
	cp -f js_require.mini.qjs js_require.tiny.qjs
endif
	@ls -l js_require.mini.qjs
	@ls -l js_require.tiny.qjs
	echo "`du -hs js_require.mini.qjs|awk '{print $$1}'` => `du -hs js_require.tiny.qjs|awk '{print $$1}'`"
	npx minify --help > /dev/null npm i minify
	npx minify --js < js_require.tiny.qjs > js_require.mini.qjs
	echo "`du -hs js_require.tiny.qjs|awk '{print $$1}'` => `du -hs mini.qjs|awk '{print $$1}'`"
	echo 'static const char *const js_require_qjs = "" \\' > js_require.c
	r2 -fqcpcc js_require.mini.qjs | grep -v ^const >> js_require.c

js_repl.c:
	# goto this s
	# 19K https://www.toptal.com/developers/javascript-minifier
	# ??K
ifeq ($(USE_MINIFY),1)
	npx minify --help > /dev/null npm i minify
	npx minify --js < js_repl.qjs > mini.qjs
else
	cp -f js_repl.qjs mini.qjs
endif
	echo "`du -hs js_repl.qjs|awk '{print $$1}'` => `du -hs mini.qjs|awk '{print $$1}'`"
ifeq ($(USE_UGLIFY),1)
	# 20K uglify
	npx uglify-js --help > /dev/null || npm i uglify-js
	npx uglify-js --no-annotations --toplevel --validate -c < mini.qjs > tiny.qjs
else
	cp -f mini.qjs tiny.qjs
endif
	@ls -l mini.qjs
	@ls -l tiny.qjs
	echo "`du -hs mini.qjs|awk '{print $$1}'` => `du -hs tiny.qjs|awk '{print $$1}'`"
	npx minify --help > /dev/null npm i minify
	npx minify --js < tiny.qjs > mini.qjs
	echo "`du -hs tiny.qjs|awk '{print $$1}'` => `du -hs mini.qjs|awk '{print $$1}'`"
	echo 'static const char *const js_repl_qjs = "" \\' > js_repl.c
	r2 -fqcpcc mini.qjs | grep -v ^const >> js_repl.c

lang_qjs.${EXT_SO}: js_repl.c js_require.c
	# $(MAKE) CFLAGS_OPT="-Oz -DCONFIG_VERSION=\\\"0.1\\\"" -C $(QJS_NAME) libquickjs.a
#-Wl,-exported_symbols_list,symbols.lst
	-$(CC) -flto -D 'CONFIG_VERSION="$(VERSION)"' -g -Oz -Wl,-dead_strip -std=c99 $(DUK_CFLAGS) -I quickjs $(QJS_CFLAGS) $(CFLAGS) -fPIC $(LDFLAGS_LIB) \
		-o lang_qjs.$(EXT_SO) $(QJS_FILES) $(QJS_LIBS) qjs.c

o:
	make clean && make && make user-install
