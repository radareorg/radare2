#!/bin/sh

if [ -z "${HOME}" ]; then
	echo "Missing HOME environment" > /dev/stderr
	exit 1
fi
PREFIX="${HOME}/.local"
make uninstall PREFIX="${PREFIX}"
