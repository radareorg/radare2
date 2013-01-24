.PHONY: index.js
all: index.js

upload:
	rsync --safe-links -avz * radare.org:/srv/http/lolcathostorg/b/

debug:
	cat js/*.js > index.js

index.js:
#	cat js/*.js > index.js
	cat js/*.js | uglifyjs > index.js || cat js/*.js > index.js
