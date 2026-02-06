project('network-manager-ms-sso', 'c',
  version: '2.0.0',
  meson_version: '>= 0.56.0',
  license: 'GPL-2.0-or-later',
  default_options: [
    'buildtype=release',
    'c_std=gnu11',
    'warning_level=2',
  ],
)

gnome = import('gnome')
i18n = import('i18n')

prefix = get_option('prefix')
datadir = join_paths(prefix, get_option('datadir'))
libdir = join_paths(prefix, get_option('libdir'))
libexecdir = join_paths(prefix, get_option('libexecdir'))
sysconfdir = get_option('sysconfdir')

# Dependencies
nm_dep = dependency('libnm', version: '>= 1.2.0')
gtk_dep = dependency('gtk4', version: '>= 4.0')
glib_dep = dependency('glib-2.0', version: '>= 2.50')
gio_dep = dependency('gio-2.0', version: '>= 2.50')

# NetworkManager VPN service directory
nm_vpnservicedir = nm_dep.get_variable(pkgconfig: 'vpnservicedir')
nm_plugindir = join_paths(libdir, 'NetworkManager')

# Configuration data
config_h = configuration_data()
config_h.set_quoted('PACKAGE_NAME', meson.project_name())
config_h.set_quoted('PACKAGE_VERSION', meson.project_version())
config_h.set_quoted('LIBEXECDIR', libexecdir)
config_h.set_quoted('SYSCONFDIR', sysconfdir)

configure_file(
  output: 'config.h',
  configuration: config_h,
)

# Build editor library
subdir('src/editor')

# Install Python service
install_data('src/nm-ms-sso-service.py',
  rename: 'nm-ms-sso-service',
  install_dir: libexecdir,
  install_mode: 'rwxr-xr-x',
)

# Install Python auth dialog
install_data('src/nm-ms-sso-auth-dialog.py',
  rename: 'nm-ms-sso-auth-dialog',
  install_dir: libexecdir,
  install_mode: 'rwxr-xr-x',
)

# Install plugin registration file
install_data('data/nm-ms-sso-service.name',
  install_dir: nm_vpnservicedir,
)

# Install D-Bus policy
install_data('data/nm-ms-sso-service.conf',
  install_dir: join_paths(datadir, 'dbus-1', 'system.d'),
)

# Core runtime is installed by packaging/install scripts from codebase/core.

# Summary
summary({
  'prefix': prefix,
  'libdir': libdir,
  'libexecdir': libexecdir,
  'NM plugin dir': nm_plugindir,
  'NM VPN service dir': nm_vpnservicedir,
}, section: 'Directories')
