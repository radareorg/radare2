# Cannot find R2PATH/format/dll/DLLNAME.sdb

1. Execute `rabin2 -rs DLLNAME.dll | grep -i DLLNAME | grep -v Ordi |grep ^k| cut -d / -f 4- > DLLNAME.sdb.txt` 
2. Upload file `DLLNAME.sdb.txt` in https://github.com/radareorg/radare2/tree/master/libr/bin/d/dll
3. Change the following [Makefile](https://github.com/radareorg/radare2/blob/master/libr/bin/d/Makefile#L14)
4. Create a Pull Request to Master
