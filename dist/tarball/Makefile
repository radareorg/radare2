VERSION=$(shell ../../configure -qV)
R2V=radare2-${VERSION}

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
	git clone ../.. $(R2V)
	-cd $(R2V) \
		&& ./preconfigure \
		&& ./configure \
		&& git log --decorate=short > ChangeLog
	rm -f $(R2V)/.test.c $(R2V)/config-user.mk \
		$(R2V)/config-user.mk $(R2V)/pkgcfg/*.pc $(R2V)/libr/include/r_userconf.h
	R2_FILES=`cd $(R2V) && git ls-files | sed -e "s,^,$(R2V)/,"` ; \
	V64_FILS=`cd $(R2V)/libr/arch/p/arm/v35/arch-arm64 ; \
		git ls-files \
		| grep -v '^\.' \
		| grep -v gitig \
		| sed -e "s,^,$(R2V)/libr/arch/p/arm/v35/arch-arm64/,"` ; \
	V32_FILS=`cd $(R2V)/libr/arch/p/arm/v35/arch-armv7 ; \
		git ls-files \
		| grep -v '^\.' \
		| grep -v gitig \
		| sed -e "s,^,$(R2V)/libr/arch/p/arm/v35/arch-armv7/,"` ; \
	rm -rf $(R2V)/subprojects/*/.git ; \
	rm -rf $(R2V)/.git ; \
	${TAR} "radare2-${VERSION}.tar" $${V64_FILS} $${V32_FILS} $${R2_FILES} $${CS_FILES} "$(R2V)/ChangeLog" ; \
	${CZ} "radare2-${VERSION}.tar"
	zip -r radare2-$(VERSION).zip radare2-$(VERSION)
