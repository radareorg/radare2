-include config.mk

all: supported.langs ruby perl python lua go

check:
	rm -f supported.langs
	${MAKE} supported.langs

supported.langs:
	CC=${CC} CXX=${CXX} sh check-langs.sh

W32PY="${HOME}/.wine/drive_c/Python27/"

check-w32:
	if [ ! -d "${W32PY}/libs" ]; then \
		wget http://www.python.org/ftp/python/2.7/python-2.7.msi ; \
		msiexec /i python-2.7.msi ; \
	fi

.PHONY: w32
w32:
	cd python && ${MAKE} w32

w32dist:
	cp python/*.dll ../radare2-w32-${VERSION}

dist:
	PKG=radare2-swig-${VERSION} ; \
	FILES=`cd .. && hg st -mac . | grep swig | sed -e "s,swig/,$${PKG}/," | cut -c 3-` ; \
	cd .. && mv swig $${PKG} && \
	echo $$FILES ; \
	tar czvf $${PKG}.tar.gz $${FILES} ; \
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

# TODO: make it less spaguetti
perl:
	@-[ "`grep perl supported.langs`" ] && cd perl && make

python:
	@-[ "`grep python supported.langs`" ] && cd python && make

ruby:
	@-[ "`grep ruby supported.langs`" ] && cd ruby && make

lua:
	@-[ "`grep lua supported.langs`" ] && cd lua && make

go:
	@-[ -x "${GOBIN}/5g" -o -x "${GOBIN}/6g" -o -x "${GOBIN}/8g" ] && \
	[ "`grep go supported.langs`" ] && cd go && make

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
	@# py2.6 in debian uses dist-packages, but site-packages in arch..
	@if [ "`grep python supported.langs`" ]; then \
	for a in python2.5/site-packages python2.6/site-packages python2.6/dist-packages; do \
	echo "Installing $$a r2 modules in ${DESTDIR}${PREFIX}/lib/$$a/r2" ; \
	mkdir -p ${DESTDIR}${PREFIX}/lib/$$a/r2 ; \
	touch ${DESTDIR}${PREFIX}/lib/$$a/r2/__init__.py ; \
	cp -rf python/*.${SOEXT} python/r_*.py python/libr.py ${DESTDIR}${PREFIX}/lib/$$a/r2 ; \
	done ; \
	fi

install-lua:
	@if [ "`grep lua supported.langs`" ]; then \
	for a in 5.1 ; do \
	mkdir -p ${DESTDIR}${PREFIX}/lib/lua/$$a/r2 ; \
	echo "Installing lua$$a r2 modules..." ; \
	cp -rf lua/*.so ${DESTDIR}${PREFIX}/lib/lua/$$a/r2 ; \
	cp -rf lua/*libr* ${DESTDIR}${PREFIX}/lib/lua/$$a ; \
	done ; \
	fi

install-go:
	@if [ -n "${GOROOT}" -a -n "${GOOS}" -a -n "${GOARCH}" ]; then \
	echo "Installing r2 modules in ${GOROOT}/pkg/${GOOS}_${GOARCH}" ; \
	cp -f go/*.a go/*.so ${GOROOT}/pkg/${GOOS}_${GOARCH} ; \
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
	cp -rf ruby/*libr* ${DESTDIR}${PREFIX}/lib/ruby/$$a ; \
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
	cp -rf perl/*libr* $$target/ ; \
	fi

install-vapi:
	@${INSTALL_DIR} ${DESTDIR}${PREFIX}/share/vala/vapi
	${INSTALL_DATA} vapi/*.vapi vapi/*.deps ${DESTDIR}${PREFIX}/share/vala/vapi

install: install-python install-ruby install-perl install-lua install-go install-java install-vapi

deinstall: uninstall
uninstall:
	cd vapi/ ; for a in *.vapi *.deps ; do rm -f ${DESTDIR}${PREFIX}/share/vala/vapi/$$a ; done

oldtest:
	sh do-swig.sh r_bp
	python test.py

clean:
	cd python && make clean
	cd perl && make clean
	cd ruby && make clean
	cd lua && make clean
	cd go && make clean
	cd java && make clean
	cd vapi/t && ${MAKE} clean

.PHONY: ruby lua go java python perl clean oldtest test all vdoc
