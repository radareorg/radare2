all:
	rabin2 -rs /tmp/ws2_32.dll | grep ^k| cut -d / -f 4- > ___WS2_32.sdb.txt
	rabin2 -rs /tmp/oleaut32.dll | grep ^k| cut -d / -f 4- > ___OLEAUT32.sdb.txt
