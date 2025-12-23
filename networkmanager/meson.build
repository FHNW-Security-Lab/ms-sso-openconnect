project(
  'nm-ms-sso-openconnect',
  'c',
  version: '0.1.0',
  default_options: [
    'c_std=c11',
    'warning_level=2',
  ],
)

dep_libnm = dependency('libnm')
dep_gmodule = dependency('gmodule-2.0')
dep_gtk4 = dependency('gtk4')

nm_libdir = join_paths(get_option('libdir'), 'NetworkManager')
nm_vpn_dir = join_paths(get_option('prefix'), 'lib', 'NetworkManager', 'VPN')
dbus_policy_dir = join_paths(get_option('datadir'), 'dbus-1', 'system.d')

library(
  'nm-vpn-plugin-ms-sso-openconnect',
  'src/nm-ms-sso-openconnect-plugin.c',
  dependencies: [dep_libnm, dep_gmodule],
  link_args: ['-ldl'],
  install: true,
  install_dir: nm_libdir,
)

library(
  'nm-gtk4-vpn-plugin-ms-sso-openconnect-editor',
  'src/nm-ms-sso-openconnect-editor-gtk4.c',
  dependencies: [dep_libnm, dep_gtk4],
  install: true,
  install_dir: nm_libdir,
)

install_data(
  'nm-ms-sso-openconnect-service.name',
  install_dir: nm_vpn_dir,
)

install_data(
  'nm-ms-sso-openconnect-service.conf',
  install_dir: dbus_policy_dir,
)

install_data(
  'src/nm-ms-sso-openconnect-service',
  install_dir: get_option('libexecdir'),
  install_mode: 'rwxr-xr-x',
)

install_data(
  'src/nm-ms-sso-openconnect-service-openconnect-helper',
  install_dir: get_option('libexecdir'),
  install_mode: 'rwxr-xr-x',
)

install_data(
  'src/nm-ms-sso-openconnect-auth-dialog',
  install_dir: get_option('libexecdir'),
  install_mode: 'rwxr-xr-x',
)

