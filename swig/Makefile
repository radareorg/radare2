-include config.mk
LANGS=python perl ruby lua go java vapi
W32PY="${HOME}/.wine/drive_c/Python27/"

ifeq ($(DEVEL_MODE),1)
all: supported.langs ruby perl python lua go
supported.langs:
	CC=${CC} CXX=${CXX} sh check-langs.sh
else
# compile more
all: supported.langs python lua
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

DSTNAME=radare2-swig-w32-$(VERSION)
DST=../$(DSTNAME)/Python27/Lib/r2

w32dist:
	mkdir -p ${DST}
	cp -f python/*.dll ${DST}
	cp -f python/r_*.py ${DST}
	cd .. ; zip -r $(DSTNAME).zip $(DSTNAME)

dist:
	PKG=radare2-swig-${VERSION} ; \
	FILES=`cd .. ; hg st -mac . | grep swig | sed -e "s,swig/,$${PKG}/," | cut -c 3-` ; \
	CXXFILES=`cd .. ; find swig | grep -e cxx$$ -e py$$ | sed -e "s,swig/,$${PKG}/,"` ; \
	cd .. && mv swig $${PKG} && \
	echo $$FILES ; \
	tar czvf $${PKG}.tar.gz $${FILES} $${CXXFILES} ; \
	mv $${PKG} swig

# TODO: valadoc
vdoc:
	-rm -rf vdoc
	cat vapi/*.vapi > libr.vapi
	valadoc -o vdoc libr.vapi
	-rm -f libr.vapi
	# rsync -avz vdoc/* pancake@radare.org:/srv/http/radareorg/vdoc/

vdoc_pkg:
	rm -rf vdoc
	valadoc -o vdoc vapi/*.vapi
	# rsync -avz vdoc/* pancake@radare.org:/srv/http/radareorg/vdoc/

# TODO: unspaguetti this targets
perl:
	@-[ "`grep perl supported.langs`" ] && cd perl && make ; true

python:
	@-[ "`grep python supported.langs`" ] && cd python && make ; true

ruby:
	@-[ "`grep ruby supported.langs`" ] && cd ruby && make ; true

lua:
	@-[ "`grep lua supported.langs`" ] && cd lua && make ; true

go:
	@-[ -x "${GOBIN}/5g" -o -x "${GOBIN}/6g" -o -x "${GOBIN}/8g" ] && \
	[ "`grep go supported.langs`" ] && cd go && make ; true

java:
	@-[ "`grep java supported.langs`" ] && cd java && make

test:
	cd perl && make test
	cd python && make test
	cd ruby && make test
	cd lua && make test
	cd go && make test
	cd java && make test

install-python:
	@# py2.6 in debian uses dist-packages, but site-packages in arch and osx..
	@if [ "`grep python supported.langs`" ]; then \
	a=python`python --version 2>&1 | cut -d ' ' -f 2 | cut -d . -f 1,2` ; \
	echo "Installing $$a/site-packages r2 modules in ${DESTDIR}${PREFIX}/lib/$$a/site-packages/r2" ; \
	mkdir -p ${DESTDIR}${PREFIX}/lib/$$a/site-packages/r2 ; \
	touch ${DESTDIR}${PREFIX}/lib/$$a/site-packages/r2/__init__.py ; \
	cp -rf python/r_*.py python/*.${SOEXT} ${DESTDIR}${PREFIX}/lib/$$a/site-packages/r2/ ; \
	echo "Installing $$a/dist-packages r2 modules in ${DESTDIR}${PREFIX}/lib/$$a/dist-packages/r2" ; \
	mkdir -p ${DESTDIR}${PREFIX}/lib/$$a/dist-packages/r2 ; \
	cp -rf python/r_*.py python/*.${SOEXT} ${DESTDIR}${PREFIX}/lib/$$a/dist-packages/r2/ ; \
	touch ${DESTDIR}${PREFIX}/lib/$$a/dist-packages/r2/__init__.py ; \
	fi

install-lua:
	@if [ "`grep lua supported.langs`" ]; then \
	for a in 5.1 ; do \
	mkdir -p ${DESTDIR}${PREFIX}/lib/lua/$$a ; \
	echo "Installing lua$$a r2 modules..." ; \
	cp -rf lua/*.${SOEXT} ${DESTDIR}${PREFIX}/lib/lua/$$a ; \
	done ; \
	fi

install-go:
	@if [ -n "${GOROOT}" -a -n "${GOOS}" -a -n "${GOARCH}" ]; then \
	echo "Installing r2 modules in ${GOROOT}/pkg/${GOOS}_${GOARCH}" ; \
	cp -f go/*.a go/*.${SOEXT} ${GOROOT}/pkg/${GOOS}_${GOARCH} ; \
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
	#@${INSTALL_DIR} ${DESTDIR}${PREFIX}/share/vala/vapi-0.12
	${INSTALL_DATA} vapi/*.vapi vapi/*.deps ${DESTDIR}${PREFIX}/share/vala/vapi
	#${INSTALL_DATA} vapi/*.vapi vapi/*.deps ${DESTDIR}${PREFIX}/share/vala/vapi-0.12

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
	for a in $(LANGS); do \
		cd $$a ; ${MAKE} clean ; cd .. ; \
	done

mrproper:
	for a in $(LANGS); do \
		cd $$a ; ${MAKE} mrproper; cd .. ; \
	done

.PHONY: $(LANGS) clean mrproper oldtest test all vdoc w32 w32dist check check-w32 deinstall uninstall install
