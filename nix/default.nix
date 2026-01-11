{ pkgs ? import <nixpkgs> { } }:

import ./packages.nix { inherit pkgs; }
