{
  outputs =
    { self }:
    let
      lock = builtins.fromJSON (builtins.readFile ./dist/nix/flake.lock);
      nixpkgsLocked = lock.nodes.nixpkgs.locked;
      nixpkgs = builtins.getFlake (
        "tarball+" + nixpkgsLocked.url + "?narHash=" + nixpkgsLocked.narHash
      );
      flake = import ./dist/nix/flake.nix;
    in
    flake.outputs {
      inherit self nixpkgs;
    };
}
