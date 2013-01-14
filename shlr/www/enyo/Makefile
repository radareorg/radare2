.PHONY: index.js
all: index.js

upload:
	rsync --safe-links -avz * radare.org:/srv/http/lolcathostorg/b/

index.js:
	cat js/*.js | uglifyjs > index.js
