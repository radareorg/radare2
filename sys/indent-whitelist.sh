#!/bin/sh
FILES="
libr/cons/hud.c
libr/cons/2048.c
libr/cons/line.c
libr/cons/canvas.c
"
if [ "$1" = commit ]; then
	sys/indent.sh -i ${FILES}
	git commit sys/indent* ${FILES}
else
	sys/indent.sh -u ${FILES}
fi
