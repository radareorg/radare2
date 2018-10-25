include ../../../global.mk
TARGET:=tags.r2

R2_FLAGS=$(DESTDIR)$(DATADIR)/radare2/$(VERSION)/flag
FILES:=$(filter-out $(TARGET),$(filter-out Makefile,$(filter-out meson.build,$(shell ls))))

all: $(TARGET)

$(TARGET): $(FILES)
	rm -f *.r2
	for a in $(FILES) ; do b=$$(echo `cat $$a`); echo "ft $$a $$b" ; done > $(TARGET)

install: $(TARGET)
	rm -rf "${R2_FLAGS}"
	mkdir -p "${R2_FLAGS}"
	cp -f *.r2 "${R2_FLAGS}"

symstall install-symlink: ${TARGET}
	mkdir -p "$(R2_FLAGS)"
	-ln -fs $(shell pwd)/tags.r2 $(R2_FLAGS)/tags.r2

uninstall:
	rm -rf "$(R2_FLAGS)"
