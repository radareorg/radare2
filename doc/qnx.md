r2 on android
=============

```
. ./bbndk-env.sh
cd ~/radare2
rm -f plugins.cfg
./configure --with-compiler=qnx --with-ostype=qnx --prefix=/accounts/devuser/radare2 --without-pic --with-nonpic
make -j 4
```

