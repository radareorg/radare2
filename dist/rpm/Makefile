all:
	rpmbuild --undefine=_disable_source_fetch  -ba radare2.spec
	cp $${HOME}/rpmbuild/RPMS/*/*.rpm .
