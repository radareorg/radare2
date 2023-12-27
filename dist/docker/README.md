# radare2 docker image

## Official stable version

The [prebuild docker image](https://hub.docker.com/r/radare/radare2) for the stable version is based on **Ubuntu** and the [radare2 snap](https://snapcraft.io/radare2) build.
The Dockerfile to build can be found in this [dedicated repository](https://github.com/radareorg/radare2-snap).
Any issue found in this packaging can be opened [there](https://github.com/radareorg/radare2-snap/issues).

The resulting build only includes the following plugins by default:

* [r2ghidra](https://github.com/radareorg/r2ghidra)
* [r2frida](https://github.com/nowsecure/r2frida) (only in supported platforms)
* [r2dec](https://github.com/wargio/r2dec-js)

### Run

To use the prebuild docker image you can use either:
```
docker run -ti radare/radare2
podman run -ti docker.io/radare/radare2
nerdctl run -ti radare/radare2
```

To use the prebuild docker image as one shot so it removes everything inside the container on exit just add `--rm` as follows:
```
docker run --rm -ti radare/radare2
```

Another example to use for debugging inside the docker:
```
docker run --tty --interactive --privileged --cap-add=SYS_PTRACE --security-opt seccomp=unconfined --security-opt apparmor=unconfined radare/radare2
```

## GIT version (r2docker)

Alternatively there is a version with radare2 GIT aimed to be build locally.

This will build an image using **Debian** with radare2 from git with latest changes.
The Dockerfile to build can be found inside this folder (`dist/docker` directory inside the radare2 source tree).

### Build from GIT

To build this other image run the following lines:

```sh
git clone https://github.com/radareorg/radare2.git
cd radare2
make -C dist/docker
```

This will build an image with the following plugins:

* [r2ghidra](https://github.com/radareorg/r2ghidra)
* [r2frida](https://github.com/nowsecure/r2frida)
* [r2dec](https://github.com/wargio/r2dec-js)

It is possible to specify more packages using the `R2PM` make variable:

```sh
make -C dist/docker R2PM=radius2
```

Also, you can select the architecture (amd64 / arm64) to compile the image by using the `ARCH` make variable.
