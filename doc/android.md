# r2 on android

## Content URIs

The `content` IO plugin opens Android `content://` URIs without converting them
to filesystem paths. It is included in the Android SDK and Termux plugin sets,
as well as the default and static builds. It needs an app resolver or Termux:API;
building for Android alone does not give a native process a ContentResolver.

### Android applications (including iaito)

Supply an `RIOContent` through the content plugin's `data` field. Its `open`
callback receives the original, still encoded URI and the requested r2
permissions. Return a newly owned POSIX file descriptor, or `-1` on failure.
For example, use `ContentResolver.openFileDescriptor(uri, "r")` and
`ParcelFileDescriptor.detachFd()` through JNI. Use `"rw"` when write access is
requested; do not use truncating modes. A descriptor must represent the whole
document, rather than a subsection returned by `openAssetFileDescriptor()`.

Keep resolver state per IO instance by copying the plugin before configuring it:

```c
RIOPlugin *builtin = r_io_plugin_resolve (io, "content://", false);
RIOPlugin content = *builtin;
RIOContent resolver = { .open = android_open_content, .user = app };
content.data = &resolver;
r_libstore_remove (io->libstore, builtin);
r_libstore_add (io->libstore, &content);
```

The plugin copy and resolver must outlive their IO instance and descriptors.
Reinstall them if the application resets the plugin list. The app owns its JNI
references and must attach native calling threads to the VM as needed. URI
grants belong to the app: acquire them through the picker and retain persistable
permissions when available so recent files and projects can reopen the URI.

The plugin closes each transferred descriptor, including on open failures.
Seekable files are accessed directly. Read-only pipes are copied to an unlinked
temporary file using a fixed-size buffer, allowing random access without loading
the whole binary into memory. Set `TMPDIR` to an app-writable cache directory.
Writable streams are rejected: modifying a local snapshot would not update the
provider. Sandbox mode blocks content opens before calling a resolver or helper.

### Termux

Without an app resolver, Android builds run `termux-saf-read` directly, passing
the URI as one argument. Install the `termux-api` package and the matching
Termux:API Android app, with a version providing the SAF commands. Grant that
app access to the document or document tree first. Then open an accessible URI:

```sh
r2 'content://provider/document/id'
```

The helper's output is stored in an unlinked temporary file. These Termux opens
are read-only snapshots; `-w` is rejected. Missing helpers and nonzero helper
exit statuses fail the open. The plugin does not bypass Android permissions.

## Building

Install NDK in archlinux x86-64

* Enable multilib repo in `pacman.conf`
* `pacman -S lib32-glibc lib32-zlib`

To build r2 for android you need to install the NDK:

* https://developer.android.com/tools/sdk/ndk/index.html

Edit `~/.r2androidrc` to setup the paths to your ndk

```
sys/android-shell.sh
./configure --with-compiler=android --with-ostype=android --prefix=/data/radare2 --without-pic --with-nonpic
make -j 4
```

To compile for android-x86

```
export NDK_ARCH=x86
```

To package:

```
make install DESTDIR=/usr
```

Build farm, see `sys/android-shell.sh` and `sys/android-build.sh`

```
sys/android-shell.sh sys/android-build.sh arm-static
```

Environment:

```
NDK_ARCH=arm|arm64|x86
```
