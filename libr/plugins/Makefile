EXTERNAL_PLUGINS=
# EXTERNAL_PLUGINS+=r2hermes
# EXTERNAL_PLUGINS+=corehi

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
	for a in $(EXTERNAL_PLUGINS) ; do echo "#include \"p/$$a/r2plugin/r2plugins.h\"" >> r2plugins.h ; done

clean:
	rm -f $(PONIS)

.PHONY: $(PONIS) clean all
