TEAPARTY=
# TEAPARTY+=corehi

all: deps.h deps.mk meson.build static.cfg

meson.build:
	:> meson.build
	for a in $(TEAPARTY) ; do echo "subdir('p/$$a')" >> meson.build ; done

static.cfg:
	:> static.cfg
	for a in $(TEAPARTY) ; do cat p/$$a/static.cfg >> static.cfg ; done

deps.mk:
	:> deps.mk
	for a in $(TEAPARTY) ; do echo "include p/$$a/deps.mk" >> deps.mk ; done

deps.h:
	:> deps.h
	for a in $(TEAPARTY) ; do echo "#include \"p/$$a/deps.h\"" >> deps.h ; done

.PHONY: deps.mk deps.h meson.build static.cfg
