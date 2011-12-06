R2=radare2
CATEGORY=security
VERSION=0.9
SRCFILE=/opt/local/etc/macports/sources.conf
ROOT=$(shell pwd)

all: setup
	sudo port -d pkg $(R2)
	cd security/${R2}/work/ && \
	sudo zip -r ${ROOT}/$(R2)-${VERSION}.pkg.zip $(R2)-${VERSION}.pkg
	

setup:
	@-[ -z "`grep -v '${PWD}' ${SRCFILE}`" ] && \
		echo "file://${PWD}" >> ${SRCFILE}
	portindex

clean:
	rm -f PortIndex*
	rm -rf `readlink security/$(R2)/work`/../../$(R2)
	rm -f security/$(R2)/work
