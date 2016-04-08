#!/bin/sh
if [ ! -d radare2-extras ]; then
	git clone https://github.com/radare/radare2-extras
fi
cd radare2-extras || exit 1
sys/yara3.sh
