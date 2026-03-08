#!/bin/sh
V=$1
[ -z "$V" ] && V="6.1.0"
wget https://github.com/radareorg/radare2/releases/download/${V}/radare2_${V}_amd64.deb
wget https://github.com/radareorg/radare2/releases/download/${V}/radare2-dev_${V}_amd64.deb
sudo dpkg -i radare2_${V}_amd64.deb
sudo dpkg -i radare2-dev_${V}_amd64.deb
