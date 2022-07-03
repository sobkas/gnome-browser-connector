project('gnome-browser-connector',
  license: 'GPL-3',
  version: run_command(
    'python3', '-c',
    'from gnome_browser_connector.version import __version__; print(__version__, end="")',
    check: true
  ).stdout(),
)

# Constants
MANIFEST_FILENAME = 'org.gnome.browser_connector.json'
MANIFEST_LEGACY_FILENAME = 'org.gnome.chrome_gnome_shell.json'

# Dependencies
python_module = import('python')
py = python_module.find_installation('python3', required: true, modules: [
  'gi'
])

# Configuration used in template files
config = configuration_data()
config.set('bindir', get_option('prefix') / get_option('bindir'))

# Install scripts
foreach script : ['gnome-browser-connector', 'gnome-browser-connector-host']
  configure_file(
    input: script,
    output: script,
    copy: true,
    install_dir: get_option('bindir'),
  )
endforeach

# Python module
install_subdir(
  'gnome_browser_connector',
  install_dir: py.get_install_dir(),
)

# Chrome/Chromium connector manifests
configure_file(
  input: 'contrib' / MANIFEST_FILENAME,
  output: MANIFEST_FILENAME,
  configuration: config,
)
configure_file(
  input: [
    meson.current_build_dir() / MANIFEST_FILENAME,
    'contrib' / MANIFEST_LEGACY_FILENAME,
  ],
  output: MANIFEST_LEGACY_FILENAME,
  command: [
    'contrib/merge_json.py',
    '--output', '@OUTPUT@',
    '@INPUT@'
  ],
)

foreach dir : ['chromium/native-messaging-hosts', 'opt/chrome/native-messaging-hosts']
  foreach file : [MANIFEST_FILENAME, MANIFEST_LEGACY_FILENAME]
    install_data(
      meson.current_build_dir() / file,
      install_dir: get_option('sysconfdir') / dir
    )
  endforeach
endforeach

# Firefox connector manifest
configure_file(
  input: [
    meson.current_build_dir() / MANIFEST_FILENAME,
    'contrib/org.gnome.browser_connector.firefox.json',
  ],
  output: 'firefox-' + MANIFEST_FILENAME,
  command: [
    'contrib/merge_json.py',
    '--delete', 'allowed_origins',
    '--output', '@OUTPUT@',
    '@INPUT@'
  ],
)
configure_file(
  input: [
    meson.current_build_dir() / ('firefox-' + MANIFEST_FILENAME),
    'contrib' / MANIFEST_LEGACY_FILENAME,
  ],
  output: 'firefox-' + MANIFEST_LEGACY_FILENAME,
  command: [
    'contrib/merge_json.py',
    '--output', '@OUTPUT@',
    '@INPUT@'
  ],
)
foreach file : [MANIFEST_FILENAME, MANIFEST_LEGACY_FILENAME]
  install_data(
    meson.current_build_dir() / ('firefox-' + file),
    install_dir: get_option('libdir') / 'mozilla/native-messaging-hosts',
    rename: file,
  )
endforeach

# DBus service
configure_file(
  input: 'contrib/org.gnome.BrowserConnector.service.in',
  output: 'org.gnome.BrowserConnector.service',
  configuration: config,
)
install_data(
  meson.current_build_dir() / 'org.gnome.BrowserConnector.service',
  install_dir: get_option('datadir') / 'dbus-1/services',
)

# Desktop file
configure_file(
  input: 'contrib/org.gnome.BrowserConnector.desktop.in',
  output: 'org.gnome.BrowserConnector.desktop',
  configuration: config,
)
install_data(
  meson.current_build_dir() /'org.gnome.BrowserConnector.desktop',
  install_dir: get_option('datadir') / 'applications',
)

# Icons
foreach size : ['16', '48', '128']
  install_data(
    'contrib/icons' / 'GnomeLogo-' + size + '.png',
    install_dir: get_option('datadir') / 'icons/hicolor' / (size + 'x' + size) / 'apps',
    rename: 'org.gnome.BrowserConnector.png'
  )
endforeach
