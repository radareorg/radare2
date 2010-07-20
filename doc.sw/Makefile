# http://nibble.develsec.org/sw.cgi/projects/sw.md

all:
	PATH=$$PWD/sw:$${PATH} sw.gen site
	md5sum site.static/*/*

clean:
	rm -rf site.static
