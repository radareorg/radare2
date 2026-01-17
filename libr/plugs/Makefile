EXTERNAL_PLUGINS=
-include config.mk

PONIS=deps.mk r2plugins.h p/meson.build static.cfg

all: $(PONIS)

p/meson.build:
	:> p/meson.build
	for a in $(EXTERNAL_PLUGINS) ; do echo "subdir('$$a/r2plugin')" >> p/meson.build ; done

static.cfg:
	:> static.cfg
	for a in $(EXTERNAL_PLUGINS) ; do cat p/$$a/r2plugin/static.cfg >> static.cfg ; done

deps.mk:
	:> deps.mk
	for a in $(EXTERNAL_PLUGINS) ; do echo "include p/$$a/r2plugin/deps.mk" >> deps.mk ; done

r2plugins.h:
	:> r2plugins.h
	for a in $(EXTERNAL_PLUGINS) ; do \
		T=`cat p/$$a/r2plugin/static.cfg | cut -d . -f 1` ; \
		echo "// includes for $$a" >> r2plugins.h ; \
		for b in $$T ; do \
			echo "// $b" >> r2plugins.h ; \
			echo "#include \"p/$$a/r2plugin/$$b/r2plugins.h\"" >> r2plugins.h ; \
		done ; \
	done

clean:
	rm -f $(PONIS)

.PHONY: $(PONIS) clean all
