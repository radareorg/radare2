TARGET:=tags.r2

R2_FLAGS=$(DESTDIR)$(DATADIR)/radare2/$(VERSION)/flag
FILES:=$(filter-out $(TARGET),$(filter-out Makefile,$(shell ls)))

all: $(TARGET)

$(TARGET): $(FILES)
	rm -f *.r2
	for a in $(FILES) ; do b=$$(echo `cat $$a`); echo "ft $$a $$b" ; done > $(TARGET)

install: $(TARGET)
	rm -rf "${R2_FLAGS}"
	mkdir -p "${R2_FLAGS}"
	cp -f *.r2 "${R2_FLAGS}"

uninstall:
	rm -rf "$(R2_FLAGS)"
