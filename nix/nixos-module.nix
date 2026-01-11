{ config, lib, pkgs, ... }:

let
  cfg = config.services.ms-sso-openconnect;
in
{
  options.services.ms-sso-openconnect = {
    enable = lib.mkEnableOption "MS SSO OpenConnect NetworkManager plugin";

    withUi = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Install the Qt UI package alongside the NetworkManager plugin.";
    };

    withOverlay = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Add the local overlay that provides the ms-sso-openconnect packages.";
    };

    autoKillStale = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Kill stale nm-ms-sso-service processes on NetworkManager restart.";
    };
  };

  config = lib.mkIf cfg.enable {
    nixpkgs.overlays = lib.optionals cfg.withOverlay [
      (import ./overlay.nix)
    ];

    networking.networkmanager.plugins = lib.mkAfter [
      pkgs.networkmanager-ms-sso
    ];

    environment.systemPackages = lib.optionals cfg.withUi [
      pkgs.ms-sso-openconnect-ui
    ];

    systemd.services.NetworkManager.serviceConfig.ExecStartPre =
      lib.optional cfg.autoKillStale
        "-${lib.getExe' pkgs.procps "pkill"} -KILL -f nm-ms-sso-service";
  };
}
