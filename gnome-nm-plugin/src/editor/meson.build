# Editor plugin library

editor_sources = files(
  'nm-ms-sso-editor.c',
)

editor_headers = files(
  'nm-ms-sso-editor.h',
)

# libsecret dependency for keyring access
secret_dep = dependency('libsecret-1', version: '>= 0.18')

# Build the shared library
editor_lib = shared_library('nm-vpn-plugin-ms-sso-editor',
  sources: editor_sources,
  dependencies: [
    nm_dep,
    gtk_dep,
    glib_dep,
    gio_dep,
    secret_dep,
  ],
  include_directories: include_directories('../..'),
  install: true,
  install_dir: join_paths(libdir, 'NetworkManager'),
)
