{ pkgs }:

let
  core = pkgs.callPackage ./ms-sso-openconnect-core.nix { };
  ui = pkgs.callPackage ./ms-sso-openconnect-ui.nix {
    ms-sso-openconnect-core = core;
  };
  nmPlugin = pkgs.callPackage ./networkmanager-ms-sso.nix {
    ms-sso-openconnect-core = core;
  };
in
{
  ms-sso-openconnect-core = core;
  ms-sso-openconnect-ui = ui;
  networkmanager-ms-sso = nmPlugin;
}
