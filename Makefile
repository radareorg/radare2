all:
	cd libr && make

clean:
	cd libr && make clean

install:
	mkdir -p prefix
	cd libr && make install PREFIX=${PWD}/prefix

deinstall:
	rm -rf prefix
