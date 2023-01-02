#!/bin/sh

export CC="tcc"
export DEBUG=0
exec sys/install.sh --with-compiler=tcc $*
