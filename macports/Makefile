VERSION=0.8.6
SRCFILE=/opt/local/etc/macports/sources.conf

all:
	sudo port pkg radare2
	zip -r radare2-${VERSION}.pkg.zip security/radare2/radare2-${VERSION}.pkg

setup:
	[ -z "`grep -v '${PWD}' ${SRCFILE}`" ] && \
		echo "file://${PWD}" >> ${SRCFILE}
	portindex
