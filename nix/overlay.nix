final: prev:

let
  packages = import ./packages.nix { pkgs = final; };
in
{
  inherit (packages)
    ms-sso-openconnect-core
    ms-sso-openconnect-ui;
}
