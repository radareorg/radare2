.PHONY: index.js
all: index.js

node_modules/.bin/uglifyjs:
	mkdir -p node_modules
	npm install uglify-js

upload:
	rsync --safe-links -avz * radare.org:/srv/http/lolcathostorg/b/

debug:
	cat js/*.js > index.js

U=node_modules/.bin/uglifyjs
index.js: $U
#	cat js/*.js > index.js
	cat js/*.js | $U > index.js || cat js/*.js > index.js
