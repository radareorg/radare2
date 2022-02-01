
.PHONY: meson meson-install meson-symstall meson-clean meson-uninstall

meson:
	@echo "[ Meson R2 Building ]"
	$(PYTHON) sys/meson.py --prefix="${PREFIX}" --shared

meson-install:
	DESTDIR="$(DESTDIR)" ninja -C build install

meson-symstall: symstall-sdb
	@echo "[ Meson symstall (not stable) ]"
	ln -fs $(PWD)/binr/r2pm/r2pm ${B}/r2pm
	ln -fs $(PWD)/binr/r2pm/r2pm.sh ${B}/r2pm.sh
	ln -fs $(PWD)/build/binr/rasm2/rasm2 ${B}/rasm2
	ln -fs $(PWD)/build/binr/rarun2/rarun2 ${B}/rarun2
	ln -fs $(PWD)/build/binr/radare2/radare2 ${B}/radare2
	ln -fs $(PWD)/build/binr/rahash2/rahash2 ${B}/rahash2
	ln -fs $(PWD)/build/binr/rabin2/rabin2 ${B}/rabin2
	ln -fs $(PWD)/build/binr/radare2/radare2 ${B}/radare2
	ln -fs $(PWD)/build/binr/ragg2/ragg2 ${B}/ragg2
	cd $(B) && ln -fs radare2 r2
	ln -fs $(PWD)/build/libr/util/libr_util.$(EXT_SO) ${L}/libr_util.$(EXT_SO)
	ln -fs $(PWD)/build/libr/bp/libr_bp.$(EXT_SO) ${L}/libr_bp.$(EXT_SO)
	ln -fs $(PWD)/build/libr/syscall/libr_syscall.$(EXT_SO) ${L}/libr_syscall.$(EXT_SO)
	ln -fs $(PWD)/build/libr/cons/libr_cons.$(EXT_SO) ${L}/libr_cons.$(EXT_SO)
	ln -fs $(PWD)/build/libr/search/libr_search.$(EXT_SO) ${L}/libr_search.$(EXT_SO)
	ln -fs $(PWD)/build/libr/magic/libr_magic.$(EXT_SO) ${L}/libr_magic.$(EXT_SO)
	ln -fs $(PWD)/build/libr/flag/libr_flag.$(EXT_SO) ${L}/libr_flag.$(EXT_SO)
	ln -fs $(PWD)/build/libr/reg/libr_reg.$(EXT_SO) ${L}/libr_reg.$(EXT_SO)
	ln -fs $(PWD)/build/libr/bin/libr_bin.$(EXT_SO) ${L}/libr_bin.$(EXT_SO)
	ln -fs $(PWD)/build/libr/config/libr_config.$(EXT_SO) ${L}/libr_config.$(EXT_SO)
	ln -fs $(PWD)/build/libr/parse/libr_parse.$(EXT_SO) ${L}/libr_parse.$(EXT_SO)
	ln -fs $(PWD)/build/libr/lang/libr_lang.$(EXT_SO) ${L}/libr_lang.$(EXT_SO)
	ln -fs $(PWD)/build/libr/asm/libr_asm.$(EXT_SO) ${L}/libr_asm.$(EXT_SO)
	ln -fs $(PWD)/build/libr/anal/libr_anal.$(EXT_SO) ${L}/libr_anal.$(EXT_SO)
	ln -fs $(PWD)/build/libr/egg/libr_egg.$(EXT_SO) ${L}/libr_egg.$(EXT_SO)
	ln -fs $(PWD)/build/libr/fs/libr_fs.$(EXT_SO) ${L}/libr_fs.$(EXT_SO)
	ln -fs $(PWD)/build/libr/debug/libr_debug.$(EXT_SO) ${L}/libr_debug.$(EXT_SO)
	ln -fs $(PWD)/build/libr/core/libr_core.$(EXT_SO) ${L}/libr_core.$(EXT_SO)

meson-uninstall:
	ninja -C build uninstall
	$(MAKE) uninstall

meson-clean:
	rm -rf build
	rm -rf build_sdb

MESON_FILES=$(shell find build/libr build/binr -type f | grep -v @)
meson-symstall-experimental:
	for a in $(MESON_FILES) ; do echo ln -fs "$(PWD)/$$a" "$(PWD)/$$(echo $$a|sed -e s,build/,,)" ; done
	$(MAKE) symstall
