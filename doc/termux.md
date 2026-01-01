# Termux

Termux is a terminal emulator that ships a base linux environment using the
Debian package system but compiling everything to run on native Android. The
result is a fully functional shell on Android devices for x86, arm and arm64.

## Installation

The Termux maintainer of the radare2 package updates the package really fast
after every release which happens every 6 weeks. So in this case, as long as
it's supposed to run on embedded devices it is ok to just install the
package from Termux unless you really want to track git master or develop
for this platform.

```sh
sudo apt install radare2
```

## Building from git

The packages required to build r2 and most of the dependencies are:

	sudo apt install make git python build-essential patch wget linux-headers

Now you can clone the repo and build:

```sh
git clone --depth 1 https://github.com/radareorg/radare2
cd radare2
sys/termux.sh
```

## Building with meson

It is also possible to install r2 with meson (muon/samu are also compatible):

```sh
sudo pip install meson ninja
```

And then you can run the build and install with meson

```sh
make meson
make meson-symstall PREFIX=/data/data/com.termux/files/usr
```

## Updating

To update the repo and rebuild you can do a full and clean rebuild by
just running `sys/termux.sh`, but `sys/install.sh` should be fine, if
there's any issue make a clean clone, uninstall and build from scratch.

```sh
make purge  # eliminate all previous installations
git reset --hard
git clean -xdf
git co master
git pull
sys/termux.sh
```
