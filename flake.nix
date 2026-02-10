{
  description = "MS SSO OpenConnect - VPN connection tool for Microsoft SSO-protected networks";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      supportedSystems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;
    in
    {
      packages = forAllSystems (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          packages = import ./nix/packages.nix { inherit pkgs; };
        in
        packages // { default = packages.networkmanager-ms-sso; }
      );

      overlays.default = import ./nix/overlay.nix;

      nixosModules.default = import ./nix/nixos-module.nix;
    };
}
