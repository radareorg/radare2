# Example custom makefile for creating .deb without using dpkg tools.
#
# Author: Tim Wegener <twegener@madabar.com>
#
# This requires deb_hand.mak

# Sources:
# SOURCE_DIR - directory containing files to be packaged
# ICON_SOURCE - 26x26 icon file for maemo
# description.txt - description with summary on first line
# preinst, postinst, prerm, postrm - optional control shell scripts

# These fields are used to build the control file.
include ./CONFIG
# todo: For python2.4 it also needs python2.4-elementtree and python2.4-sqlite
DEPENDS =
# todo: Recommends
PACKAGE_DIR=${PWD}

SOURCE_DIR = .
ICON_SOURCE =
#ICON_SOURCE =${SOURCE_DIR}/maemo_deb/exaile26.png
PRG=../../../build/default/
PRG=../../../
SPRG=../../../

all:
	sudo rm -rf control data
	${MAKE} clean
	${MAKE} control
	${MAKE} deb

${PACKAGE_DIR}/data: ${SOURCE_DIR}
	echo $@
	sudo rm -rf data
	mkdir -p $@
	-cd .. ; fakeroot ${MAKE} install DESTDIR=$@ INSTALL_PROGRAM=cp
	sudo chown -R 0:0 $@/*
	ls -al data/usr/bin/
	mkdir -p control
	printf "S 15 com.nokia.maemo H 40 " > control/digisums
	printf `sha1sum $@/../data/usr/bin/radare2` >> control/digisums
	echo "R 25 usr/bin/radare2" >> control/digisums

jiji:
	rm -rf $@
	mkdir $@
	cd .. ; ${MAKE} install INSTALL_PROGRAM=cp DESTDIR=maemo/$@

jajaj:
	mkdir -p $@/usr/bin $@/usr/share/doc/radare $@/usr/share/radare/ $@/usr/libexec/gradare $@/usr/share/radare/rsc $@/usr/lib $@/usr/share/radare/magic
	#radare
	-cp ${PRG}/src/radiff/radiff $@/usr/bin/radiff
	#-cp ${PRG}/src/rsc/pool/bindiff $@/usr/bin/bindiff
	-cp ${PRG}/src/radare $@/usr/bin/radare
	-cp ${PRG}/src/rabin/rabin $@/usr/bin/rabin
	-cp ${PRG}/src/rasm/rasm $@/usr/bin/rasm
	-cp ${PRG}/src/rasc/rasc $@/usr/bin/rasc
	-cp ${PRG}/src/arch/arm/aasm/armasm $@/usr/bin/armasm
	-cp ${PRG}/src/rsc/rsc $@/usr/bin/rsc
	-cp ${PRG}/src/rfile $@/usr/bin/rfile
	-cp ${PRG}/src/rahash/rahash $@/usr/bin/rahash
	-cp ${PRG}/src/rax $@/usr/bin/rax
	-cp ${PRG}/src/xrefs $@/usr/bin/xrefs
	-cp ${PRG}/src/javasm/javasm $@/usr/bin/javasm
	-cp ${PRG}/gui/gradare $@/usr/bin/gradare
	-cp /usr/bin/gtkdialog $@/usr/bin/gtkdialog
	#-cp /usr/lib/libvte.so.4 $@/usr/lib
	mkdir -p $@/usr/share/radare/gradare
	-cp -rf ${SPRG}/gui/grsc/* $@/usr/share/radare/gradare
	-cp -rf ${SPRG}/src/rsc/pool/* $@/usr/share/radare/rsc
	-cp -rf ${SPRG}/magic/* $@/usr/share/radare/magic/
	-cp -rf ${SPRG}/doc/* $@/usr/share/doc/radare/
	-chmod +x $@/usr/bin/*
	mkdir -p $@/usr/share/applications/hildon/
	-cp ${SPRG}/gui/gradare.desktop $@/usr/share/applications/hildon/

include deb_hand.mak
