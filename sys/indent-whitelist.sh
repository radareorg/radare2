#!/bin/sh
FILES="
libr/cons/hud.c
libr/cons/2048.c
libr/cons/line.c
libr/cons/canvas.c
libr/cons/editor.c
libr/util/base64.c
libr/util/name.c
libr/util/stack.c
libr/util/slist.c
libr/util/log.c
libr/util/cache.c
"
if [ "$1" = commit ]; then
	sys/indent.sh -i ${FILES}
	git commit sys/indent* ${FILES}
else
	sys/indent.sh -u ${FILES}
fi
