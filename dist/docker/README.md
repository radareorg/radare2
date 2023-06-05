# r2docker

To build the image and get a shell run the following line

```
docker run -ti radare/radare2
```

It is also possible to specify which r2pm packages to be compiled into the image to make them persistent across runs. Share the folder you like from your host with `-v` to get files. Debugging

## Building

The source code of this Dockerfile is inside the `dist/docker` directory inside the  radare2 source tree.

```sh
make -C dist/docker
```

Note that this makefile will build an image using Debian11 with r2 from git and the following plugins:

* r2frida
* r2ghidra
* r2dec

It is possible to specify more packages using the `R2PM` make variable:

```sh
make -C dist/docker R2PM=radius2
```

## Debugging

The makefile in dist/docker takes care about passing the right flags to get ptrace support inside the image. Also, you can select the architecture (amd64 / arm64) to compile the image and run it. This is what it does under the hood:

```sh
docker run -ti r2docker --privileged --cap-add=SYS_PTRACE --security-opt seccomp=unconfined --security-opt apparmor=unconfined
```

## Links

You can read more about the project in the following links

* https://www.radare.org
* https://github.com/radareorg/radare2

