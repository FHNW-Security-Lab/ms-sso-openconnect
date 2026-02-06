{ lib
, python3Packages
, qt6
, openconnect
, polkit
, procps
, playwright-driver
, ms-sso-openconnect-core
}:

python3Packages.buildPythonApplication rec {
  pname = "ms-sso-openconnect-ui";
  version = "2.0.0";
  pyproject = true;

  src = ../codebase/ui;

  nativeBuildInputs = [
    qt6.wrapQtAppsHook
  ];

  buildInputs = [
    qt6.qtwayland
    qt6.qtsvg
    playwright-driver
  ];

  build-system = with python3Packages; [
    setuptools
    wheel
  ];

  dependencies = with python3Packages; [
    pyqt6
    keyring
    pyotp
    playwright
    secretstorage
    ms-sso-openconnect-core
  ];

  makeWrapperArgs = [
    "--prefix" "PATH" ":" (lib.makeBinPath [ openconnect polkit procps ])
    "--run" ''
      pw_cache="$HOME/.cache/ms-playwright"
      if [ ! -e "$pw_cache" ]; then
        mkdir -p "$HOME/.cache"
        ln -s "${playwright-driver.browsers}" "$pw_cache"
      fi
    ''
  ];

  dontWrapQtApps = true;
  preFixup = ''
    makeWrapperArgs+=("''${qtWrapperArgs[@]}")
  '';

  postInstall = ''
    install -Dm644 ${../frontends/linux/packaging/desktop/ms-sso-openconnect-ui.desktop} -t $out/share/applications
    install -Dm644 src/vpn_ui/resources/icons/app-icon.svg \
      $out/share/icons/hicolor/scalable/apps/ms-sso-openconnect-ui.svg
    install -Dm644 ${../frontends/linux/packaging/polkit/org.openconnect.policy} \
      $out/share/polkit-1/actions/org.openconnect.policy

    substituteInPlace $out/share/polkit-1/actions/org.openconnect.policy \
      --replace /usr/sbin/openconnect ${lib.getExe' openconnect "openconnect"} \
      --replace /usr/bin/pkill ${lib.getExe' procps "pkill"}
  '';

  doCheck = false;
  pythonImportsCheck = [ "vpn_ui" ];

  meta = with lib; {
    description = "Qt6 GUI for MS SSO OpenConnect";
    homepage = "https://github.com/FHNW-Security-Lab/ms-sso-openconnect";
    license = licenses.mit;
    mainProgram = "ms-sso-openconnect-ui";
    platforms = platforms.linux;
  };
}
