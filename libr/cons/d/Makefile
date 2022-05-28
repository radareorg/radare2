include ../../../config-user.mk
P=${DESTDIR}${DATADIR}/radare2/${VERSION}/cons

all clean:

.PHONY: all clean install install-symlink symstall

CWD=$(shell pwd)

themes.c:
	:> themes.c
	THEMES="" ; \
	for FILE in * ; do \
		if [ $$FILE != themes.c -a $$FILE != Makefile -a $$FILE != meson.build -a -f $$FILE ]; then \
			echo "static const char *theme_$$FILE = \\" >> themes.c ; \
			cat "${CWD}/$$FILE" | sed -e 's,",\\",g' -e 's,^,\t",' -e 's,$$,\\n",' >> themes.c ; \
			echo ";" >> themes.c ; \
			THEMES="$$THEMES $$FILE" ; \
		fi ; \
	done ; \
	echo "typedef struct {const char *name; const char **script; } RConsTheme;" >> themes.c ; \
	echo "RConsTheme r_cons_themes[] = {" >> themes.c ; \
	for a in $$THEMES ; do \
		echo "	{ \"$$a\", &theme_$$a }," >> themes.c ; \
	done ; \
	echo "	{0,0}" >> themes.c ; \
	echo "};" >> themes.c

install: ${F_SDB}
	rm -rf "$P"
	mkdir -p "$P"
	for FILE in * ; do \
		if [ $$FILE != Makefile -a $$FILE != meson.build -a -f $$FILE ]; then \
			cp -PRpf "${CWD}/$$FILE" "$P/$$FILE" ; \
		fi ; \
	done

symstall install-symlink:
	mkdir -p "$P"
	for FILE in * ; do \
		if [ $$FILE != Makefile -a $$FILE != meson.build -a -f $$FILE ]; then \
			ln -fs "${CWD}/$$FILE" "$P/$$FILE" ; \
		fi ; \
	done

uninstall:
	rm -rf "$P"
