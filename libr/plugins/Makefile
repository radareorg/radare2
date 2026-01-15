TEAPARTY=
# TEAPARTY+=corehi

PONIS=deps.mk deps.h p/meson.build static.cfg

all: $(PONIS)

p/meson.build:
	:> p/meson.build
	for a in $(TEAPARTY) ; do echo "subdir('p/$$a')" >> p/meson.build ; done

static.cfg:
	:> static.cfg
	for a in $(TEAPARTY) ; do cat p/$$a/static.cfg >> static.cfg ; done

deps.mk:
	:> deps.mk
	for a in $(TEAPARTY) ; do echo "include p/$$a/deps.mk" >> deps.mk ; done

deps.h:
	:> deps.h
	for a in $(TEAPARTY) ; do echo "#include \"p/$$a/deps.h\"" >> deps.h ; done

clean:
	rm -f $(PONIS)

.PHONY: $(PONIS) clean all
