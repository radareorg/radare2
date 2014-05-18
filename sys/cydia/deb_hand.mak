# Create .deb without using dpkg tools.
#
# Author: Tim Wegener <twegener@madabar.com>
#
# Use 'include deb_hand.mak' after defining the user variables in a local
# makefile.
#
# The 'data' rule must be customised in the local make file.
# This rule should make a 'data' directory containing the full file
# layout of the installed package.
#
# This makefile will create a debian-binary file a control directory and a
# a build directory in the current directory.
# Do 'make clobber' to remove these generated files.
#
# Destination:
# PACKAGE_DIR - directory where package (and support files) will be built
#               defaults to the current directory
#
# Sources:
# SOURCE_DIR - directory containing files to be packaged
# ICON_SOURCE - 26x26 icon file for maemo
# DESCR - description with summary on first line
# preinst, postinst, prerm, postrm - optional control shell scripts

# These fields are used to build the control file:
# PACKAGE = 
# VERSION = 
# ARCH = 
# SECTION = 
# PRIORITY = 
# MAINTAINER = 
# DEPENDS = 
#
# SOURCE_DIR =
# ICON_SOURCE = 
# (ICON_SOURCE is optional)

# *** NO USER CHANGES REQUIRED BEYOND THIS POINT ***
ifeq ($(shell uname),Darwin)
MD5SUM=md5
else
MD5SUM=md5sum
endif

GAWK=awk
PACKAGE_DIR?=$(shell pwd)
CONTROL_EXTRAS ?= ${wildcard preinst postinst prerm postrm}

${PACKAGE_DIR}/control: ${PACKAGE_DIR}/data ${CONTROL_EXTRAS} DESCR \
			${ICON_SOURCE}
	#rm -rf $@
	mkdir -p $@
ifneq (${CONTROL_EXTRAS},)
	cp ${CONTROL_EXTRAS} $@
endif
#       Make control file.
	echo "Package: ${PACKAGE}" > $@/control
	echo "Version: ${VERSION}" >> $@/control
	echo "Section: ${SECTION}" >> $@/control
	echo "Priority: ${PRIORITY}" >> $@/control
	echo "Architecture: ${ARCH}" >> $@/control
ifneq (${DEPENDS},)
	echo "Depends: ${DEPENDS}" >> $@/control
endif
	echo "Installed-Size: ${shell du -s ${PACKAGE_DIR}/data|cut -f1}" \
		>> $@/control
	echo "Maintainer: ${MAINTAINER}" >> $@/control
	printf "Description:" >> $@/control
	cat DESCR | ${GAWK} '{print " "$$0;}' >> $@/control
#ifneq (${ICON_SOURCE},)
#	echo "Maemo-Icon-26:" >> $@/control
#	base64 ${ICON_SOURCE} | ${GAWK} '{print " "$$0;}' >> $@/control
#endif
#       Make md5sums.
	cd ${PACKAGE_DIR}/data && find . -type f -exec ${MD5SUM} {} \; \
		| sed -e 's| \./||' \
		> $@/md5sums

${PACKAGE_DIR}/debian-binary:
	echo "2.0" > $@

${PACKAGE_DIR}/clean:
	rm -rf ${PACKAGE_DIR}/data ${PACKAGE_DIR}/control ${PACKAGE_DIR}/build *.deb

${PACKAGE_DIR}/build: ${PACKAGE_DIR}/debian-binary ${PACKAGE_DIR}/control \
			${PACKAGE_DIR}/data
	rm -rf $@
	mkdir $@
	cp ${PACKAGE_DIR}/debian-binary $@/
	cd ${PACKAGE_DIR}/control && tar czvf $@/control.tar.gz *
	cd ${PACKAGE_DIR}/data && \
		COPY_EXTENDED_ATTRIBUTES_DISABLE=true \
		COPYFILE_DISABLE=true \
		tar cpzvf $@/data.tar.gz ./*

# Convert GNU ar to BSD ar that debian requires.
# Note: Order of files within ar archive is important!
${PACKAGE_DIR}/${PACKAGE}_${VERSION}_${ARCH}.deb: ${PACKAGE_DIR}/build
	ar -rc $@ $</debian-binary $</control.tar.gz $</data.tar.gz
	#sed -e 's|^\([^/]\+\)/ \(.*\)|\1  \2|g' $@tmp > $@fail
	#rm -f $@tmp
	#mv $@fail $@

.PHONY: data
data: ${PACKAGE_DIR}/data

.PHONY: control
control: ${PACKAGE_DIR}/control

.PHONY: build
build: ${PACKAGE_DIR}/build

.PHONY: clean
clean: ${PACKAGE_DIR}/clean
	rm -f debian-binary

.PHONY: deb
deb: ${PACKAGE_DIR}/${PACKAGE}_${VERSION}_${ARCH}.deb


clobber::
	rm -rf ${PACKAGE_DIR}/debian_binary ${PACKAGE_DIR}/control \
		${PACKAGE_DIR}/data ${PACKAGE_DIR}/build

push:
	scp *.deb radare.org:/srv/http/radareorg/cydia/debs
