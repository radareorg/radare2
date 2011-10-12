#!/bin/sh

cd `dirname $PWD/$0`
b=log/bin
p=`../../configure --version|head -n1|cut -d ' ' -f 1`

rm -rf $b/*
mkdir -p $b
os=`uname -sm|sed -e 's, ,-,'|tr 'A-Z' 'a-z'`
cp ../../$p-bin.tar.gz $b/$p-$os.tar.gz
cp ../../$p-android*.gz $b
cp ../../radare2-*.zip $b
cp ../../r2-bindings-0.8.5.tar.gz $b
