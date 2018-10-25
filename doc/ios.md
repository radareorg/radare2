iOS
===

Code signing on iOS is simpler, because the Jailbreak simplifies the process (Compared to OSX), but you will probably be debugging as root, as long as everyone runs stuff as root on their iDevices..

Compilation
-----------

There are different ways to build r2 for iOS, use the sys/ script you need:

* `sys/ios-cydia.sh`
* `sys/ios-static.sh`
* `sys/ios-simulator.sh`

It is also possible to build r2 natively on your iDevice by following the standard `./configure ; make ; make install` steps. But if you own a Mac is better to use the XCode toolchain to get better build times.

For incremental compilations or daily development you should:

	$ sys/ios-sdk.sh -s

To get a shell with all the environment variables set to build for iOS instead of Mac.

Signing
-------

Codesigning on iOS can be done by using the following command:

	$ make -C binr/radare2 ios-sign

Note that iOS signing is done by embedding an `entitlements` PLIST file instead of the `Info.plist` as required in OSX. This file describes all the specific fine-grained permissions that the application will need. It is also important to note that if you add an entitlement to an OSX binary it will be forbidden to run.

Packaging
---------
If you have used `sys/ios-cydia.sh` you should get already two Cydia packages, one with bins and another with libs for `-dev`, if not, just run this command:

	$ make -C sys/cydia

Installation
------------

The Cydia packages can be installed by copying the binary:

	$ ssh root@192.168.0.13
	# rm -f radare2
	$ scp binr/radare2 root@192.168.0.13:.

Note that it is important to remove the previous executable from the filesystem because `ldone` signing is associated with the filesystem inode, and it will fail to run if you overwrite the contents of the executable without removing it first.

Installing the `cydia.radare.org` repository.

	# apt-get update
	# apt-install radare2

Or just doing it from the command line:

	# dpkg -i radare2-*.deb
