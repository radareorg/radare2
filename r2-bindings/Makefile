-include config.mk
PYTHON2_CONFIG=python2.7-config
PYTHON3_CONFIG=python3.2-config

ifneq ($(shell bsdtar -h 2>/dev/null|grep bsdtar),)
TAR=bsdtar czvf
else
TAR=tar -czvf
endif

LANGS=python perl ruby lua go java guile gear gir

W32PY="${HOME}/.wine/drive_c/Python27/"

ifeq ($(DEVEL_MODE),1)
all: supported.langs ruby perl python lua go gear gir
supported.langs:
	CC=${CC} CXX=${CXX} sh check-langs.sh
else
# compile more
all: supported.langs python lua gear gir
supported.langs:
	CC=${CC} CXX=${CXX} sh check-langs.sh force-all
endif

chect:
	rm -f supported.langs
	${MAKE} supported.langs

check-w32:
	if [ ! -d "${W32PY}/libs" ]; then \
		wget http://www.python.org/ftp/python/2.7/python-2.7.msi ; \
		msiexec /i python-2.7.msi ; \
	fi

w32:
	cd python && ${MAKE} w32

DSTNAME=radare2-bindings-w32-$(VERSION)
DST=../$(DSTNAME)/Python27/Lib/r2

w32dist:
	rm -rf ${DST}/*
	mkdir -p ${DST}
	cp -f python/*.dll ${DST}
	cp -f python/r_*.py ${DST}
	cd .. ; zip -r $(DSTNAME).zip $(DSTNAME)

.PHONY: w32dist dist w32 check check-w32 vdoc vdoc_pkg

dist:
	PKG=r2-bindings-${VERSION} ; \
	FILES=`cd .. ; hg st -mac . | grep r2-bindings | grep -v '/\.' | sed -e "s,r2-bindings/,$${PKG}/," | cut -c 3-` ; \
	CXXFILES=`cd .. ; find r2-bindings | grep -e cxx$$ -e py$$ | sed -e "s,r2-bindings/,$${PKG}/,"` ; \
	cd .. && mv r2-bindings $${PKG} && \
	echo $$FILES ; \
	${TAR} $${PKG}.tar.gz $${FILES} $${CXXFILES} ; \
	mv $${PKG} r2-bindings

# TODO: valadoc
vdoc:
	-rm -rf vdoc
	cat vapi/r_*.vapi > libr.vapi
	valadoc --package-version=${VERSION} --package-name=libr --driver 0.13.x -o vdoc libr.vapi
	-rm -f libr.vapi
	# rsync -avz vdoc/* pancake@radare.org:/srv/http/radareorg/vdoc/

vdoc_pkg:
	rm -rf vdoc
	valadoc -o vdoc vapi/*.vapi
	# rsync -avz vdoc/* pancake@radare.org:/srv/http/radareorg/vdoc/

gear:
	cd gear && ${MAKE}

# TODO: unspaguetti this targets
perl:
	@-[ "`grep perl supported.langs`" ] && ( cd perl && ${MAKE} ) || true

python2:
	@-[ "`grep python supported.langs`" ] && ( cd python && ${MAKE} PYTHON_CONFIG=${PYTHON2_CONFIG}) || true

python3:
	@-[ "`grep python supported.langs`" ] && ( cd python && ${MAKE} PYTHON_CONFIG=${PYTHON3_CONFIG}) || true

python:
	@-[ "`grep python supported.langs`" ] && ( cd python && ${MAKE} ) || true

guile:
	@-[ "`grep guile supported.langs`" ] && ( cd guile && ${MAKE} ) || true

ruby:
	@-[ "`grep ruby supported.langs`" ] && ( cd ruby && ${MAKE} ) || true

lua:
	@-[ "`grep lua supported.langs`" ] && ( cd lua && ${MAKE} ) || true

go:
	@-[ -x "${GOBIN}/5g" -o -x "${GOBIN}/6g" -o -x "${GOBIN}/8g" ] && \
	[ "`grep go supported.langs`" ] && ( cd go && ${MAKE} ) || true

java:
	@-[ "`grep java supported.langs`" ] && ( cd java && ${MAKE} ) || true

gir:
	@-[ "`grep gir supported.langs`" ] && ( cd gir && ${MAKE} ) || true

test:
	cd perl && ${MAKE} test
	cd python && ${MAKE} test
	cd ruby && ${MAKE} test
	cd lua && ${MAKE} test
	cd guile && ${MAKE} test
	cd go && ${MAKE} test
	cd java && ${MAKE} test

PYTHON_VERSION?=`python --version 2>&1 | cut -d ' ' -f 2 | cut -d . -f 1,2`

install-python:
	@# py2.6 in debian uses dist-packages, but site-packages in arch and osx..
	echo "Using python version: ${PYTHON_VERSION}"
	@if [ "`grep python supported.langs`" ]; then \
	E=${SOEXT} ; \
	[ `uname` = Darwin ] && E=so ; \
	a=python${PYTHON_VERSION} ; \
	echo "Installing $$a/dist-packages r2 modules in ${DESTDIR}${PREFIX}/lib/$$a/dist-packages/r2" ; \
	mkdir -p ${DESTDIR}${PREFIX}/lib/$$a/dist-packages/r2 ; \
	cp -rf python/r_*.py python/*.$$E ${DESTDIR}${PREFIX}/lib/$$a/dist-packages/r2/ ; \
	touch ${DESTDIR}${PREFIX}/lib/$$a/dist-packages/r2/__init__.py ; \
	fi

#	echo "Installing $$a/site-packages r2 modules in ${DESTDIR}${PREFIX}/lib/$$a/site-packages/r2" ; \
#	mkdir -p ${DESTDIR}${PREFIX}/lib/$$a/site-packages/r2 ; \
#	touch ${DESTDIR}${PREFIX}/lib/$$a/site-packages/r2/__init__.py ; \
#	cp -rf python/r_*.py python/*.$$E ${DESTDIR}${PREFIX}/lib/$$a/site-packages/r2/ ; \

install-lua:
	@if [ "`grep lua supported.langs`" ]; then \
	for a in 5.1 ; do \
	mkdir -p ${DESTDIR}${PREFIX}/lib/lua/$$a ; \
	echo "Installing lua$$a r2 modules..." ; \
	cp -rf lua/*.${SOEXT} ${DESTDIR}${PREFIX}/lib/lua/$$a ; \
	done ; \
	fi

install-go:
	@. ./go/goenv.sh ; \
	if [ -n "$${GOROOT}" -a -n "$${GOOS}" -a -n "$${GOARCH}" ]; then \
	echo "Installing r2 modules in $${GOROOT}/pkg/$${GOOS}_$${GOARCH}" ; \
	cp -f go/*.a go/*.${SOEXT} $${GOROOT}/pkg/$${GOOS}_$${GOARCH} ; \
	else \
	echo "You have to set the following vars: GOROOT, GOOS and GOARCH" ; \
	fi

install-java:
	@echo "TODO: install-java"

install-ruby:
	@if [ "`grep ruby supported.langs`" ]; then \
	for a in 1.8 1.9.1; do \
	mkdir -p ${DESTDIR}${PREFIX}/lib/ruby/$$a/r2 ; \
	echo "Installing ruby$$a r2 modules..." ; \
	cp -rf ruby/* ${DESTDIR}${PREFIX}/lib/ruby/$$a/r2 ; \
	done ; \
	fi

install-guile:
	@echo TODO: install-guile

install-perl:
	# hack for slpm
	@-if [ "`grep perl supported.langs`" ]; then \
	if [ -n "`echo ${PREFIX}${DESTDIR}|grep home`" ]; then \
		target=${PREFIX}${DESTDIR}`perl -e 'for (@INC) { print "$$_\n" if /lib(64)?\/perl5/ && !/local/; }'|head -n 1` ; \
	else \
		target=${DESTDIR}`perl -e 'for (@INC) { print "$$_\n" if /lib(64)?\/perl5/ && !/local/; }'|head -n 1` ; \
	fi ; \
	mkdir -p $$target/r2 ; \
	echo "Installing perl r2 modules..." ; \
	cp -rf perl/*.so $$target/r2 ; \
	cp -rf perl/*.pm $$target/r2 ; \
	fi

install-vapi:
	@${INSTALL_DIR} ${DESTDIR}${PREFIX}/share/vala/vapi
	${INSTALL_DATA} vapi/*.vapi vapi/*.deps ${DESTDIR}${PREFIX}/share/vala/vapi

EXAMPLEDIR=${DESTDIR}${PREFIX}/share/radare2-swig
install-examples: install-examples-python
	mkdir -p ${EXAMPLEDIR}/vala
	cp -rf vapi/t/*.vala vapi/t/*.gs ${EXAMPLEDIR}/vala

install-examples-python:
	if [ "`grep python supported.langs`" ]; then \
		mkdir -p ${EXAMPLEDIR}/python ; \
		cp -rf python/test-*.py ${EXAMPLEDIR}/python ; \
	fi

install: install-python install-ruby install-perl install-lua install-go install-java install-vapi install-examples

deinstall: uninstall
uninstall:
	cd vapi/ ; for a in *.vapi *.deps ; do rm -f ${DESTDIR}${PREFIX}/share/vala/vapi/$$a ; done
	rm -rf ${EXAMPLEDIR}

oldtest:
	sh do-swig.sh r_bp
	python test.py

clean:
	@for a in $(LANGS); do \
		echo "Cleaning $$a " ; \
		cd $$a ; ${MAKE} clean ; cd .. ; \
	done

mrproper:
	for a in $(LANGS); do \
		cd $$a ; ${MAKE} mrproper; cd .. ; \
	done

.PHONY: $(LANGS) clean mrproper oldtest test all vdoc w32 w32dist check check-w32 deinstall uninstall install
