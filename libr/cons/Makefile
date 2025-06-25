include ../config.mk

NAME=r_cons
OBJS=cons.o cpipe.o winutils.o grep.o less.o pager.o cutf8.o
OBJS+=line.o hud.o rgb.o input.o pal.o editor.o 2048.o
OBJS+=canvas.o canvas_line.o stiv.o pixel.o help.o visual.o
R2DEPS=r_util

include ../rules.mk

line.o: dietline.c

kons:
	git grep r_kons *| grep 'inc.c'|cut -d : -f 2-| grep R_API | sed -e 's/) {/);/'
