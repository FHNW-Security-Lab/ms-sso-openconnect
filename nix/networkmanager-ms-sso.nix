{ lib
, python3Packages
, meson
, ninja
, pkg-config
, wrapGAppsHook4
, networkmanager
, gtk4
, glib
, libadwaita
, libsecret
, openconnect
, vpnc-scripts
, writeShellScriptBin
, iproute2
, procps
, playwright-driver
, ms-sso-openconnect-core
}:

let
  openconnectWrapped = writeShellScriptBin "openconnect" ''
    exec ${lib.getExe openconnect} --script ${lib.getExe' vpnc-scripts "vpnc-script"} "$@"
  '';
in
python3Packages.buildPythonApplication rec {
  pname = "networkmanager-ms-sso";
  version = "2.0.0";
  format = "other";

  src = lib.cleanSource ../frontends/gnome-plugin;

  nativeBuildInputs = [
    meson
    ninja
    pkg-config
    wrapGAppsHook4
  ];

  buildInputs = [
    networkmanager
    gtk4
    glib
    libadwaita
    libsecret
    playwright-driver
  ];

  pythonPath = with python3Packages; [
    pygobject3
    dbus-python
    keyring
    secretstorage
    pyotp
    playwright
    ms-sso-openconnect-core
  ];

  makeWrapperArgs = [
    "--prefix" "PATH" ":" (lib.makeBinPath [
      openconnectWrapped
      openconnect
      iproute2
      procps
    ])
    "--set" "HOME" "/var/cache/ms-sso-openconnect"
    "--set" "SUDO_USER" "ms-sso-openconnect"
    "--set" "PLAYWRIGHT_BROWSERS_PATH" "/var/cache/ms-playwright"
    "--set" "XDG_CACHE_HOME" "/var/cache/ms-sso-openconnect/.cache"
    "--prefix" "GI_TYPELIB_PATH" ":" (lib.makeSearchPath "lib/girepository-1.0" [
      networkmanager
      gtk4
      libadwaita
      libsecret
      glib
    ])
  ];

  postPatch = ''
    sed -i '/# Install core Python module/,/^)$/d' meson.build
  '';

  PKG_CONFIG_LIBNM_VPNSERVICEDIR = "${placeholder "out"}/lib/NetworkManager/VPN";

  dontWrapGApps = true;
  preFixup = ''
    makeWrapperArgs+=("''${gappsWrapperArgs[@]}")
  '';

  postFixup = ''
    wrapPythonProgramsIn "$out/libexec" "$out $pythonPath"
  '';

  postInstall = ''
    substituteInPlace $out/lib/NetworkManager/VPN/nm-ms-sso-service.name \
      --replace /usr/libexec "$out/libexec" \
      --replace "plugin=libnm-vpn-plugin-ms-sso-editor.so" \
        "plugin=$out/lib/NetworkManager/libnm-vpn-plugin-ms-sso-editor.so"
  '';

  passthru = {
    networkManagerPlugin = "VPN/nm-ms-sso-service.name";
    networkManagerRuntimeDeps = [ openconnect vpnc-scripts iproute2 procps ];
    networkManagerTmpfilesRules = [
      "L+ /var/cache/ms-playwright - - - - ${playwright-driver.browsers}"
      "d /var/cache/ms-sso-openconnect 0755 root root -"
    ];
  };

  doCheck = false;

  meta = with lib; {
    description = "NetworkManager VPN plugin for MS SSO OpenConnect";
    homepage = "https://github.com/FHNW-Security-Lab/ms-sso-openconnect";
    license = licenses.gpl2Plus;
    platforms = platforms.linux;
  };
}
