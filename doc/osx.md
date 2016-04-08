OSX
===

Mac OS-X Users need to follow some extra steps to get the radare2 program signed and ready to debug other applications without running it as root. Same happens for iOS users, read `doc/ios` for more information.

Installation
------------

To compile for OSX automatically, do it this way:

	$ sys/install.sh

By default it is installed in /usr/local, you can specify a different prefix like this:

	$ sys/install.sh /custom/prefix

To install bindings you will need to install r2, valac, valabind and swig. The whole process can be automated by using scripts under sys/

	$ sys/python-deps.sh
	$ sys/python.sh


Code Signing
------------

After OSX 10.6, binaries that need permissions to debug require to be signed and include a PLIST describing them. In order to do this you can follow the following steps:

(Based on https://llvm.org/svn/llvm-project/lldb/trunk/docs/code-signing.txt)

	- Launch /Applications/Utilities/Keychain Access.app
	- In Keychain Access select the "login" keychain in the "Keychains" list in the upper left hand corner of the window.
	- Select the following menu item:
		Keychain Access->Certificate Assistant->Create a Certificate...
	- Set the following settings
		Name = org.radare.radare2
		Identity Type = Self Signed Root
		Certificate Type = Code Signing
	- Click Create
	- Click Continue
	- Click Done
	- Click on the "My Certificates"
	- Double click on your new org.radare.radare2 certificate
	- Turn down the "Trust" disclosure triangle, scroll to the "Code Signing" trust pulldown menu and select "Always Trust" and authenticate as needed using your username and password.
	- Drag the new "org.radare.radare2" code signing certificate (not the public or private keys of the same name) from the "login" keychain to the "System" keychain in the Keychains pane on the left hand side of the main Keychain Access window. This will move this certificate to the "System" keychain. You'll have to authorize a few more times, set it to be "Always trusted" when asked.
	- In the Keychain Access GUI, click and drag "org.radare.radare2" in the "System" keychain onto the desktop. The drag will create a "~/Desktop/org.radare.radare2.cer" file used in the next step.
	- Switch to Terminal, and run the following:
		$ sudo security add-trust -d -r trustRoot -p basic -p codeSign -k /Library/Keychains/System.keychain ~/Desktop/org.radare.radare2.cer
		$ rm -f ~/Desktop/org.radare.radare2.cer
	- Drag the "org.radare.radare2" certificate from the "System" keychain back into the "login" keychain
	- Quit Keychain Access
	- Reboot
	- Run sys/install.sh (or follow the next steps if you want to install and sign radare2 manually)

As said before, the signing process can also be done manually following the next process. First, you will need to sign the radare2 binary:

	$ make -C binr/radare2 osxsign

But this is not enough. As long as r2 code is splitted into several libraries, you should sign every single dependency (libr*).

	$ make -C binr/radare2 osx-sign-libs

Another alternative is to build a static version of r2 and just sign it.

	$ sys/static.sh
	$ make -C binr/radare2 osxsign

You can verify that the binary is properly signed and verified by the code signing utility:

	$ codesign -dv binr/radare2/radare2

After doing it you should be able to debug on OSX without root permissions!

	$ r2 -d ls

Note: if you already have a valid certifcate for code signing, you can specify its name by setting the env var CERTID.

Packaging
---------

To create an OSX .pkg just run the following command:

	$ sys/osx-pkg.sh
