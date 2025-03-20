# Native Windows Builds

These are the standard instructions to build radare2 on Windows, keep
reading for alternative methods below.

You can follow the [r2book](https://radare.gitbooks.io/radare2book/content/first_steps/windows_compilation.html) for a more complete guide.

## Requirements

You will need:

* Python 3 with pip3
* Meson and ninja (pip3 install meson)
* Visual Studio 2019 (2015 and 2022 should work too)

## Compilation

The easiest way to build is by using the batch scripts:

```
preconfigure.bat
configure.bat
make.bat
```

The first one will setup the python and visual studio in PATH, you
only need to run it once per console.

The second will run meson under the hood and create the `b` and `vs`
directories to build using `ninja` or `visual studio` project.

Finally the `make` will run `ninja` and create the `prefix` directory
containing all the distribution binaries, libraries and support files.

## Running

Check the `prefix\bin` directory and type `radare2`

## Debugging

If you experience any segfault you can start the VS debugger from `cmd.exe`
using the following line:

```console
devenv /DebugExe radare2.exe rax2.exe
```

After starting the process, vs will take the source information and display
the stacktrace, variable values and so on, fix the code, run `make.bat` and
try again until the bug is gone.

# Crosscompilation

Run `sys/mingw32.sh` or `sys/mingw64.sh` to crosscompile r2 from Linux/macOS
to 32 or 64bit Windows using `acr/make`.

# Blob builds

The `binr/blob` directory contains the program that acts like `busybox` but
for `r2`. Rename the executable to any of the collection and it will act
accordingly.

This is, a single executable, with no external libraries that you can drop
anywhere easily, 3rd party plugins won't work well with it, but it's useful
to have in a variety of situations.

## Compiling the blob for windows

Follow the **native build instructions** and just pass an argument to the
second step:

```
configure.bat static
make.bat
```

# Continuous Integration

You can also check the CI scripts under `.github/workflow` to see the steps
performed to generate the release builds for Windows.

Most notabily there are some 3rd party bugs that we cannot handle and they
are workarounded in the environment setup.

## Troubleshooting

* meson have race condition bugs that force you to compile with `ninja -j1`
* Some recent versions of pip generate bogus wrapper programs for meson
* Visual Studio 2022 may not be supported out of the box yet
* Python PATH can break over shells, better use pyenv as `preconfigure.bat` does
