Compilation instructions
========================

To get python bindings for radare2 you need to install the following dependencies:

* swig
	* svn co https://swig.svn.sourceforge.net/svnroot/swig/trunk
* valaswig
	* hg clone http://hg.youterm.com/valaswig
* radare2
	* hg clone http://radare.org/hg/radare2

Then, you have to compile r2-swig:

	$ cd radare2/swig
	$ ./configure --prefix=/usr
	$ make
	$ sudo make install
