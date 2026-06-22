# Nix

radare2 provides a Nix flake for reproducible builds and development shells.

```sh
nix run github:radareorg/radare2?dir=dist/nix     # run radare2
nix shell github:radareorg/radare2?dir=dist/nix   # shell with r2 in PATH
nix build github:radareorg/radare2?dir=dist/nix   # build the package
```

For development, clone the repo and use the dev shell:

```sh
git clone https://github.com/radareorg/radare2
cd radare2
nix develop ./dist/nix   # enter dev shell with all build dependencies
nix build ./dist/nix     # build from local source
```
