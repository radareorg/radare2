Build for maemo6 (Harmattan) N9 - N950
======================================

1. Install QtSDK 

       http://qt.nokia.com/downloads/

2. Configure mad (maemo development environment)

       cd /usr/bin ; sudo ln -fs $HOME/QtSDK/Madde/bin/mad
       mad set harmattan-nokia-meego-api
       mad sh

3. Compile

       ./configure --prefix=/usr --with-little-endian \
           --with-compiler=mad --with-ostype=gnulinux
       make

4. Create the package

       cd maemo
       make

5. Install the package

       dpkg -i radare2-*.deb
