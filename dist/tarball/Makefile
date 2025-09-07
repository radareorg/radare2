.PHONY: all clean
VERSION=$(shell ../../configure -qV)
R2V=radare2-${VERSION}
GIT_TIP=HEAD

ifneq ($(shell xz --help 2>/dev/null | grep improve),)
TAR=tar -cvf
TAREXT=tar.xz
CZ=xz -f
else
TAR=bsdtar cvf
TAREXT=tar.gz
CZ=gzip -f
endif

all:
	rm -rf $(R2V)
	mkdir $(R2V)
	git -C ../.. archive $(GIT_TIP) | tar -x -C $(R2V)
	git log --decorate=short $(GIT_TIP) > $(R2V)/ChangeLog

# Subprojects
	make -C $(R2V)/subprojects all
	rm -rf $(R2V)/subprojects/*/.git
	mv $(R2V)/subprojects/Makefile $(R2V)/subprojects/Makefile.orig
	echo "default:" > $(R2V)/subprojects/Makefile

# Cleanup
	rm -rf $(R2V)/preconfigure* $(R2V)/.github

# Archive
	${TAR} "radare2-${VERSION}.tar" $(R2V) ; \
	${CZ} "radare2-${VERSION}.tar"
	zip -r radare2-$(VERSION).zip $(R2V)

clean:
	rm -rf radare2-$(VERSION).zip radare2-$(VERSION).tar* radare2-$(VERSION)
