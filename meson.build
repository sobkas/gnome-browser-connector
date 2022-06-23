project('gnome-browser-connector',
  license: 'GPL-3',
  version: run_command(
    'python3', '-c',
    'from gnome_browser_connector import __version__; print(__version__, end="")',
    check: true
  ).stdout(),
)

# Dependencies
python_module = import('python')
py = python_module.find_installation('python3', required: true, modules: [
  'gi',
  'requests'
])

# Configuration used in template files
config = configuration_data()
config.set('bindir', get_option('prefix') / get_option('bindir'))

# Install main script
configure_file(
  input: 'gnome-browser-connector',
  output: 'gnome-browser-connector',
  copy: true,
  install_dir: get_option('bindir'),
)

# Python module
install_subdir(
  'gnome_browser_connector',
  install_dir: py.get_install_dir(),
)

# Chrome/Chromium connector manifests
configure_file(
  input: 'contrib/org.gnome.chrome_gnome_shell.json',
  output: 'org.gnome.chrome_gnome_shell.json',
  configuration: config,
)

foreach dir : ['chromium/native-messaging-hosts', 'opt/chrome/native-messaging-hosts']
  install_data(
    meson.current_build_dir() / 'org.gnome.chrome_gnome_shell.json',
    install_dir: get_option('sysconfdir') / dir
  )
endforeach

# Firefox connector manifest
configure_file(
  input: [
    meson.current_build_dir() / 'org.gnome.chrome_gnome_shell.json',
    'contrib/org.gnome.chrome_gnome_shell.firefox.json',
  ],
  output: 'org.gnome.chrome_gnome_shell.firefox.json',
  command: [
    'contrib/merge_json.py',
    '--delete', 'allowed_origins',
    '--output', '@OUTPUT@',
    '@INPUT@'
  ],
)
install_data(
  meson.current_build_dir() / 'org.gnome.chrome_gnome_shell.firefox.json',
  install_dir: get_option('libdir') / 'mozilla/native-messaging-hosts',
  rename: ['org.gnome.chrome_gnome_shell.json']
)

# DBus service
configure_file(
  input: 'contrib/org.gnome.ChromeGnomeShell.service.in',
  output: 'org.gnome.ChromeGnomeShell.service',
  configuration: config,
)
install_data(
  meson.current_build_dir() / 'org.gnome.ChromeGnomeShell.service',
  install_dir: get_option('datadir') / 'dbus-1/services',
)

# Desktop file
install_data(
  'contrib/org.gnome.ChromeGnomeShell.desktop',
  install_dir: get_option('datadir') / 'applications',
)

# Icons
foreach size : ['16', '48', '128']
  install_data(
    'contrib/icons' / 'GnomeLogo-' + size + '.png',
    install_dir: get_option('datadir') / 'icons/hicolor' / (size + 'x' + size) / 'apps',
    rename: 'org.gnome.ChromeGnomeShell.png'
  )
endforeach
