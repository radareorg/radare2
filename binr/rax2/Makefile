BIN=rax2
BINDEPS=r_util

include ../rules.mk

U=$(LTOP)/../shlr/www/enyo/node_modules/uglify-js/bin/uglifyjs 

$U:
	cd $(LTOP)/../shlr/www/enyo ; ${MAKE}

rax2.min.js: $U
	$U < rax2.js > rax2.min.js

pub: rax2.min.js
	scp index.html main.js rax2.min.js radare.org:/srv/http/radareorg/js/rax2
