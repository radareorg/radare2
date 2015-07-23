OSX
===

Mac OS-X Users need to follow some extra steps to get the radare2 program signed and ready to debug other applications without running it as root. Same happens for iOS users, read `doc/ios` for more information.

Installation
------------

To compile for OSX run configure in this way:

	$ sys/install.sh

By default it is installed in /usr, you can specify a different prefix like this:

	$ sys/install.sh /usr/local

To install bindings you will need to install r2, valac, valabind and swig. The whole process can be automated by using scripts under sys/

	$ sys/python-deps.sh
	$ sys/python.sh


Code Signing
------------

After OSX 10.6, binaries that need permissions to debug require to be signed and include a PLIST describing them. This process differs from the steps needed for iOS, so please read the `doc/ios` for further details.

- The first step requires creating a self signed system certificate for code signing, Open the `KeyChain Access` application and start the wizard found in:

	Menu -> CertificateAssistant -> Create Certificate
	-> certificate type: code signing

	Use organization: radare.org
	Name: org.radare.radare2

Once created, right click on certificate and:

	-> Trust options -> Always trust

Then you can sign the binary by using the following command:

	$ make -C binr/radare2 osxsign

But this is not all! As long as r2 code is splitted into several libraries, you should sign every single dependency (libr*) by typing the system password all the time. For simplicity, I would recommend you to build a static version of r2 and just sign it.

	$ sys/static.sh
	$ make -C binr/radare2 osxsign

You can verify that the binary is properly signed and verified by the code signing utility:

	$ codesign -v binr/radare2/radare2

So let's check what the sandboxing thinks about it:

	$ spctl -av radare2
	radare2: accepted
	override=security disabled

If this command says `rejected` instead of `accepted` it is probably because of your system settings. So launch the *System Preferences* application and:

	-> Security & Privacy
	-> General
	-> Allow Apps Downloaded From
		-> Anywhere

Because our signing hasnt been done from an apple verified account we have to mark this option and then manually restart `taskgated` to make it happen!

	$ sudo killall taskgated

After this confirm it with the `spctl` tool and you should be able to debug on OSX without root permissions!

	$ r2 -d ls

If you want to run and sign a dynamically linked version of radare2 you will get the following error:

	$ codesign -dv binr/radare2/radare2
	binr/radare2/radare2: code object is not signed at all

Follow those steps to fix this issue:

	$ make -C binr/radare2 osx-sign-libs

And run `codesign -dv` and `spctl -av` to confirm.

Troubleshooting
---------------
Make sure that taskgated runs with -p by editing `com.apple.taskgated.plist`:

	<key>ProgramArguments</key> 
	<array> 
		<string>/usr/libexec/taskgated</string> 
		<string>-p</string> 
		<string>-s</string> 
	</array>

Then run those lines:

	launchctl unload /System/Library/LaunchDaemons/com.apple.taskgated.plist
	sudo vim /System/Library/LaunchDaemons/com.apple.taskgated.plist
	launchctl load /System/Library/LaunchDaemons/com.apple.taskgated.plist


To root your certificate read the following instructions:

https://llvm.org/svn/llvm-project/lldb/trunk/docs/code-signing.txt

	sudo security add-trust -d -r trustRoot \
		-p basic -p codeSign \
		-k /Library/Keychains/System.keychain \
		~/Desktop/org.radare.radare2.cer

And then reboot!

Packaging
---------

To create an OSX .pkg just run the following command:

	$ sys/osx-pkg.sh
