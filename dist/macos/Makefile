all:
	cd ../.. && sys/osx-pkg.sh
	cp -f ../../sys/osx-pkg/*.pkg .

install:
	installer -pkg *.pkg -target /

clean:
	rm -rf *.pkg
