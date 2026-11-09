VERSION=$(shell ../../configure -qV)
R2V=radare2-$(VERSION)

all:
	mkdir -p $${HOME}/rpmbuild/SOURCES
	git -C ../.. archive --prefix=$(R2V)/ --output="$$HOME/rpmbuild/SOURCES/$(R2V).tar.gz" HEAD
	rpmbuild --define 'r2version $(VERSION)' -ba radare2.spec
	cp $${HOME}/rpmbuild/RPMS/*/*.rpm .
