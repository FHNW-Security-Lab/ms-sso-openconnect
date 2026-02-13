VERSION ?= 2.0.0

.PHONY: help appimage deb linux-all pkg nix nix-core nix-ui

help:
	@./build/build.sh help

appimage:
	@./build/build.sh appimage $(VERSION)

deb:
	@./build/build.sh deb $(VERSION)

linux-all:
	@./build/build.sh linux-all $(VERSION)

pkg:
	@./build/build.sh pkg $(VERSION)

nix:
	@./build/build.sh nix all

nix-core:
	@./build/build.sh nix core

nix-ui:
	@./build/build.sh nix ui
