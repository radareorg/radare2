LANG=node-ffi
MODVER=$(shell node -e 'console.log(JSON.parse(require("fs").readFileSync("package.json"))["version"])')
LANG_EXT=js
LIBS_PFX=
FORCE_SOEXT=1
SAVED=index.js

.PHONY: bar all
bar: node_modules all

include ../rules.mk

node_modules:
	npm install

npm publish: clean
	${MAKE}
	npm publish

unpublish: clean
	${MAKE}
	npm unpublish @${MODVER}
