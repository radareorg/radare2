# macOS

macOS Users need to follow some extra steps to get the radare2 program signed and ready to debug other applications without running it as root. Same happens for iOS users, read `doc/ios` for more information.

## Installation

To compile for macOS automatically, do it this way:

```sh
$ sys/install.sh
```

## Common Issues

### Arm64e debug targets

When running radare2 on arm64e processors, it is necessary to build radare2 for this specific architecture, because it is required to work with the pointer authentication stuff. To do this you'll need to:

* Disable SIP (Enter recovery mode and run `csrutil disable`)
* Set some specific CFLAGS to build r2
* Set a custom boot argument for the kernel

Use this script snippet as inspiration to achieve it:

```sh
sudo nvram boot-args=-arm64e_preview_abi
sudo reboot
```

```sh
export CFLAGS="-arch arm64e"
sys/install.sh
```

### Codesigning Requirement For Debugging

If you want to use the debugger via ssh or the sdk was not properly setup you must run:

```sh
$ sudo DevToolsSecurity -enable
```

You cannot debug binaries located outside your home, if you want to do that you should disable SIP:

* Reboot your mac while pressing CMD+R to enter recovery mode
* Open the terminal in the Utilities menu and type:

```sh
$ csrutil disable
```

## Code Signing

After Mac OS X 10.6, binaries that need permissions to debug require to be signed and include a .plist describing them. The aforementioned `install.sh` script will install a new code signing certificate into the system keychain and sign r2 with it. Alternatively, you can manually create a code signing certificate by following the following steps:

(Based on https://llvm.org/svn/llvm-project/lldb/trunk/docs/code-signing.txt)

* Launch /Applications/Utilities/Keychain Access.app
* In Keychain Access select the "login" keychain in the "Keychains" list in the upper left hand corner of the window.
* Select the following menu item:
* Keychain Access->Certificate Assistant->Create a Certificate...
* Set the following settings
* Name = org.radare.radare2
* Identity Type = Self Signed Root
* Certificate Type = Code Signing
* Click Create
* Click Continue
* Click Done
* Click on the "My Certificates"
* Double click on your new org.radare.radare2 certificate
* Turn down the "Trust" disclosure triangle, scroll to the "Code Signing" trust pulldown menu and select "Always Trust" and authenticate as needed using your username and password.
* Drag the new "org.radare.radare2" code signing certificate (not the public or private keys of the same name) from the "login" keychain to the "System" keychain in the Keychains pane on the left hand side of the main Keychain Access window. This will move this certificate to the "System" keychain. You'll have to authorize a few more times, set it to be "Always trusted" when asked.
* In the Keychain Access GUI, click and drag "org.radare.radare2" in the "System" keychain onto the desktop. The drag will create a "~/Desktop/org.radare.radare2.cer" file used in the next step.
* Switch to Terminal, and run the following:
* $ sudo security add-trust -d -r trustRoot -p basic -p codeSign -k /Library/Keychains/System.keychain ~/Desktop/org.radare.radare2.cer
* $ rm -f ~/Desktop/org.radare.radare2.cer
* Quit Keychain Access
* Reboot
* Run sys/install.sh (or follow the next steps if you want to install and sign radare2 manually)

As said before, the signing process can also be done manually following the next process. First, you will need to sign the radare2 binary:

```sh
$ make -C binr/radare2 macossign
```

But this is not enough. As long as r2 code is split into several libraries, you should sign every single dependency (libr*).

	$ make -C binr/radare2 macos-sign-libs

Another alternative is to build a static version of r2 and just sign it.

	$ sys/static.sh
	$ make -C binr/radare2 macossign

You can verify that the binary is properly signed and verified by using the code signing utility:

	$ codesign -dv binr/radare2/radare2

Additionally, you can run the following command to add the non-privileged user (username) to the Developer Tools group in macOS, avoiding the related Xcode prompts:

	$ sudo dscl . append /Groups/_developer GroupMembership <username>

After doing it you should be able to debug on macOS without root permissions!

	$ r2 -d mybin

Note: if you already have a valid certificate for code signing, you can specify its name by setting the env var CERTID.

## Packaging

To create a macOS .pkg just run the following command:

	$ sys/osx-pkg.sh

## Uninstall

To uninstall the .pkg downloaded from the r2 website or the one you have generated with `sys/osx-pkg.sh`, run the following as root:

	$ pkgutil --only-files --files org.radare.radare2 | sed 's/^/\//' | tr '\n' '\0' | xargs -o -n 1 -0 rm -i

