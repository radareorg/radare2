# Nix

radare2 provides a Nix flake for reproducible builds and development shells.
The repository root contains a small redirect shim, while the Nix packaging and
lock file live in this directory.

```sh
nix run github:radareorg/radare2     # run radare2
nix shell github:radareorg/radare2   # shell with r2 in PATH
nix build github:radareorg/radare2   # build the package
```

For development, clone the repo and use the dev shell:

```sh
git clone https://github.com/radareorg/radare2
cd radare2
nix develop   # enter dev shell with all build dependencies
nix build     # build from local source
```
