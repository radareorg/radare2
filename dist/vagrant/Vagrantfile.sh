#!/bin/sh

# Updates
sudo pacman -Syu

git clone --depth=1 https://github.com/radareorg/radare2
cd radare2 && ./sys/install.sh
