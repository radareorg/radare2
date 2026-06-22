{
  inputs.nixpkgs.url = "https://channels.nixos.org/nixos-unstable/nixexprs.tar.xz";

  outputs =
    {
      self,
      nixpkgs,
    }:
    let
      inherit (nixpkgs) lib;

      pkgsFor = system: nixpkgs.legacyPackages.${system} or (import nixpkgs { inherit system; });

      supportedSystems = builtins.filter (
        system: (builtins.tryEval (pkgsFor system).stdenv.hostPlatform).success
      ) (lib.systems.doubles.linux ++ lib.systems.doubles.darwin);

      forAllSystems = function: lib.genAttrs supportedSystems (system: function (pkgsFor system));

      ciSystems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
      ];
    in
    {
      overlays.default = final: _: {
        radare2 = final.callPackage ./package.nix { src = self; };
      };

      packages = forAllSystems (pkgs: {
        radare2 = pkgs.callPackage ./package.nix { src = self; };
        default = self.packages.${pkgs.stdenv.hostPlatform.system}.radare2;
      });

      checks = lib.genAttrs ciSystems (system: self.packages.${system});

      devShells = forAllSystems (pkgs: {
        default = import ./shell.nix { inherit pkgs; };
      });

      formatter = forAllSystems (pkgs: pkgs.nixfmt-rfc-style);
    };
}