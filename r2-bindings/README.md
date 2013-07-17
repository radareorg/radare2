
   ===============
  =               =
  =  R2-Bindings  =  Language bindings for r2 api
  =               =
   ===============   --pancake



Description
===========

This directory contains the code necessary to use the r2 api from your
favourite language.

It supports a large list of programming languages:

  - Vala, Genie, Java, Go, Python, Ruby, Perl, LUA, NewLisp, Guile

And some other experimental bindings are for:

  - GIR, C++

This package also contains the vdoc/ subdirectory which contains the
rules used to generate all interactive html documentation found at:

   http://radare.org/vdoc


Dependencies
============

To build r2-bindings from repository you need the following programs installed:

  * swig: enables support for python, perl, lua, java and many other
  * vala: if you want to have Vala or Genie bindings
  * valabind: required only in developer mode (not release tarball)

Release tarballs come with all the pregenerated .cxx files, so you have
no extra dependencies apart from the language libraries and C++ compiler.

To get install all dependencies do the following steps in order:

  * Install swig and mercurial from repository
    (ensure you don't have vala installed from package)

       arch$ sudo pacman -S swig mercurial git
       deb$ sudo apt-get install swig mercurial

  * Install latest release of Vala from tarball

      http://live.gnome.org/Vala

      ./configure --prefix=/usr
      make
      sudo make install
  
  * Clone vala compiler from git repository:

      $ git clone git://git.gnome.org/vala
      $ cd vala
      $ sh autogen.sh --prefix=/usr
      $ make
      $ sudo make install

  * Fetch valabind from the repository:
 
      $ hg clone http://hg.youterm.com/valabind
      $ cd valabind
      $ make
      $ sudo make install PREFIX=/usr


To keep bindings up-to-date
===========================

When changes are done in libr an ABI break can occur. The bindings will require
to be recompiled to work again.

It's recommendable to keep your system always up to date, and upgrade vala
and valabind from git/hg.

   $ cd vala
   $ git pull
   $ make
   $ sudo make install

   $ cd ../valabind
   $ hg pull -u
   $ make
   $ sudo make install PREFIX=/usr


r2-bindings
===========

If you compile from the repo you need the latest version of valabind and then:

  ./configure --prefix=/usr

You can select the languages you want to compile with --enable={list-of-langs}

  ./configure --prefix=/usr --enable=python


PYTHON
======

To select the version of python to compile for use the PYTHON_CONFIG
environment variable as follows:

  $ ./configure --prefix=/usr --enable-devel
  $ cd python
  $ PYTHON_CONFIG=python2.7-config make
  $ su -
  # PYTHON_CONFIG=python2.7-config make install


RANDOM NOTES
===========

The valabind integration forces us to do some changes in the r2 API.

These api changes are for:

  - Avoid keywords in function names

    Every language has its own keywords, r2api should try to workaround
    all those keywords to avoid collisions for bindings.

    Example: use, del, from, continue, etc..

    TODO: we need to review APIs, find better names for functions using
    those keywords, etc..

  - Review basic data structures

    Linked lists, hash tables, r_db, arrays, ... must be reviewed to
    fit with vala and swig basics to be able to use them with simple
    APIs or integrate them with the syntax sugar of the target language.

    Example:
      foreach (var foo in binls.get_symbols ()) {
        print ("%s 0x%08"PFMT64x"\n", foo.name, foo.offset);
      }

  - Unit testing

    Having bindings for python, perl, ruby, .. is good for unit testing
    because it hardly simplifies the way to test APIs, find bugs, ...

    TODO: write unit testing frameworks for perl, ruby, python, etc..

  - API unification for all languages

    All the previous development points are meant to reduce code in r2,
    avoid syntax exceptions, simplify api usage, and much moar ;)

SWIG is not complete, there are still so many bugs to fix and so many
unimplemented stuff. Here's a list of the most anoying things of it:

  - unsigned char * : not implemented
