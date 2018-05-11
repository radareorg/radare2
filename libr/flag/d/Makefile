#TODO: this makefile is not called yet. we need to test and improve that for the next release

FILES:=$(filter-out ft.r2,$(filter-out Makefile,$(shell ls)))

all: ft.r2

ft.r2: $(FILES)
	for a in $(FILES) ; do b=$$(echo `cat $$a`); echo "ft $$a $$b" ; done > ft.r2
