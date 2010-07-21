# http://nibble.develsec.org/sw.cgi/projects/sw.md

all:
	PATH=$$PWD/sw:$${PATH} sw.gen site
	md5sum site.static/*/*
	for a in `find site.static/ -type d` ; do cp style.css $$a ; done

sync:
	rsync -avz site.static/* radare.org:/srv/http/radareorg/doc/sw/

clean:
	rm -rf site.static
