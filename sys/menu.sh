#!/bin/sh

dialog -h 2> /dev/null
if [ $? != 0 ]; then
	if [ "`uname`" = Darwin ]; then
		brew install dialog || exit 1
	else
		echo "Cannot find dialog in PATH" >&2
		exit 1
	fi
fi

CaptureOutput="2>.nconfig.tmp"
GetOutput() {
	cat .nconfig.tmp
}

Todo() {
	dialog --infobox "$1" 0 0
	sleep 2
}

MainMenu() {
	while : ; do
		#dialog --checklist foo 30 30 20 foo foo1 foo2 bar bar1 bar2
		dialog --menu "radare2 build" 0 0 0 \
			"Load plugins profile" . \
			"Select plugins" . \
			"Build & Install" . \
			"Packages" . \
			"Cleanup" . \
			"Quit" . 2>.nconfig.tmp || exit 1
		case $(GetOutput) in
		Quit)
			return
			;;
		"Build & Install")
			BuildAndInstall
			;;
		"Select plugins")
			SelectPlugin
			;;
		"Cleanup")
			Cleanup
			;;
		"Packages")
			Packages
			;;
		"Load plugins profile")
			SelectConfig
			;;
		esac
	done
}


SelectPlugin () {
	SelectPluginStatic
	SelectPluginShared
	./configure-plugins
}

SelectPluginShared () {
	PLUGINS="`diff plugins .static.plugins | grep "<" | awk '{print $2}'`"
	ARGS=""
	for a in ${PLUGINS} ; do
		ARGS="${ARGS} $a . on"
	done
	dialog --checklist "Select Shared Plugins" 0 0 0 ${ARGS}  2> .nconfig.tmp
	OPT=$(<.nconfig.tmp)
	echo "SHARED=\"" >> plugins.cfg
	echo $OPT >> plugins.cfg
	echo "\"" >> plugins.cfg
	rm .static.plugins
}

SelectPluginStatic() {
	. ./dist/plugins-cfg/plugins.def.cfg
	PLUGINS="${STATIC} ${SHARED}"
	ARGS=""
	for a in ${PLUGINS} ; do
		ARGS="${ARGS} $a . on"
	done
	dialog --checklist "Select Static Plugins" 0 0 0 ${ARGS}  2> .nconfig.tmp
	OPT=$(<.nconfig.tmp)
	echo "STATIC=\"" > plugins.cfg
	echo $OPT >> plugins.cfg
	echo $OPT | tr " " "\n" > .static.plugins
	echo "\"" >> plugins.cfg
}

Packages() {
	while : ; do
		dialog --menu "radare2 packages" 0 0 0 \
			"Install packages" . \
			"Uninstall packages" . \
			"Update all packages" . \
			"Quit" . 2>.nconfig.tmp || exit 1
		case $(GetOutput) in
		Quit)
			return
			;;
		"Install packages")
			PackagesInstall
			;;
		"Uninstall packages")
			PackagesUninstall
			;;
		"Update all packages")
			# TODO: add a flag for this
			for a in `r2pm -l` ; do r2pm -i $a ; done
			;;
		esac
	done
}

PackagesInstall() {
	PLUGINS="`r2pm -lu`"
	ARGS=""
	for a in ${PLUGINS} ; do
		ARGS="${ARGS} $a . off"
	done
	dialog --checklist "Select packages to install" 0 0 0 ${ARGS} 2> .nconfig.tmp
	OPT=$(<.nconfig.tmp)
	echo
	if [ -n "${OPT}" ]; then
		for a in ${OPT} ; do
			r2pm -i "$a"
			sleep 1
		done
	fi
}

PackagesUninstall() {
	PLUGINS="`r2pm -l`"
	ARGS=""
	for a in ${PLUGINS} ; do
		ARGS="${ARGS} $a . off"
	done
	dialog --checklist "Select packages to uninstall" 0 0 0 ${ARGS} 2> .nconfig.tmp
	OPT=$(<.nconfig.tmp)
	if [ -n "${OPT}" ]; then
		for a in ${OPT} ; do
			r2pm -u "$a"
			sleep 1
		done
	fi
}

Cleanup() {
	while : ; do
		dialog --menu "radare2 build" 0 0 0 \
			"Uninstall" . \
			"Purge previous installations" . \
			"make clean" . \
			"make mrproper" . \
			"git clean -xdf" . \
			"Quit" . 2>.nconfig.tmp || exit 1
		case $(GetOutput) in
		'make uninstall')
			sudo make uninstall
			;;
		'Purge previous installations')
			sudo make purge
			;;
		'make clean')
			make clean
			;;
		'make mrproper')
			make mrproper
			;;
		'git clean -xdf')
			git clean -xdf
			;;
		Quit)
			return
			;;
		esac
	done
}

BuildAndInstall() {
	while : ; do
		#dialog --checklist foo 30 30 20 foo foo1 foo2 bar bar1 bar2
		dialog --menu "radare2 build" 0 0 0 \
			"System build" . \
			"Home build" . \
			"iOS" . \
			"Windows" . \
			"Android ARM" . \
			"Android MIPS" . \
			"Android X86" . \
			"Quit" . 2>.nconfig.tmp || exit 1
		case $(GetOutput) in
		Quit)
			return
			;;
		"System build")
			KEEP_PLUGINS_CFG=1 sys/install.sh
			;;
		"Home build")
			KEEP_PLUGINS_CFG=1 sys/user.sh
			;;
		"iOS")
			sys/ios-sdk.sh
			;;
		"OSX")
			sys/osx-pkg.sh
			;;
		"Windows")
			sys/mingw32.sh
			;;
		"Android ARM64")
			sys/android-build.sh arm64
			;;
		"Android ARM")
			sys/android-build.sh arm
			;;
		"Android MIPS")
			sys/android-build.sh mips
			;;
		"Android X86")
			sys/android-build.sh x86
			;;
		esac
	done
}

ConfigurePlugins() {
	#dialog --checklist foo 30 30 20 foo foo1 foo2 bar bar1 bar2
	ARGS=""
	dialog --menu "radare2 build" 0 0 0 ${ARGS}
}

SelectConfig() {
	PLUGINS="`ls *.cfg | grep -v plugins.cfg`"
	ARGS=""
	for a in ${PLUGINS} ; do
		ARGS="${ARGS} $a . on"
	done
	dialog --radiolist "Select plugins profile" 0 0 0 ${ARGS} 2> .nconfig.tmp
	OPT=$(<.nconfig.tmp)
	echo
	echo "Selected ${OPT}"
	if [ -n "${OPT}" -a -f "${OPT}" ]; then
		cp -f ${OPT} plugins.cfg
		./configure-plugins
	fi
}

(
	rm -f .nconfig.tmp
	MainMenu
	rm -f .nconfig.tmp
)
