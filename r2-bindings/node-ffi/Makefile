LANG=node-ffi
LANG_EXT=js
LIBS_PFX=
FORCE_SOEXT=1
SAVED=index.js

.PHONY: bar all
bar: node_modules all

include ../rules.mk

node_modules:
	npm install

npm: clean
	${MAKE}
	npm publish
