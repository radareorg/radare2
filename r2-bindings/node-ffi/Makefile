LANG=node-ffi
LANG_EXT=js
LIBS_PFX=
FORCE_SOEXT=1
SAVED=test.js test2.js

include ../rules.mk

npm:
	rm -rf node_modules/r2
	mkdir -p node_modules/r2
	${MAKE}
	cp package.json node_modules/r2/
	cp r_core.js node_modules/r2/index.js
	sed -e 's,./r_asm,r2,' test.js > node_modules/r2/test.js
	sed -e 's,./r_asm,r2,' test2.js > node_modules/r2/test2.js
	npm publish
