#!/usr/bin/env python

'''
    GNOME Shell integration for Chrome
    Copyright (C) 2016  Yuri Konotopov <ykonotopov@gmail.com>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
'''

from __future__ import unicode_literals
from __future__ import print_function
from gi.repository import GLib, Gio
import json
import os
import re
import requests
import signal
import struct
import sys
import traceback

CONNECTOR_VERSION	= 7.1
DEBUG_ENABLED		= False

SHELL_SCHEMA = "org.gnome.shell"
ENABLED_EXTENSIONS_KEY = "enabled-extensions"
EXTENSION_DISABLE_VERSION_CHECK_KEY = "disable-extension-version-validation"

# https://developer.chrome.com/extensions/nativeMessaging#native-messaging-host-protocol
MESSAGE_LENGTH_SIZE = 4

# https://wiki.gnome.org/Projects/GnomeShell/Extensions/UUIDGuidelines
def isUUID(uuid):
    return uuid is not None and re.match('[-a-zA-Z0-9@._]+$', uuid) is not None


def debug(message):
    if DEBUG_ENABLED:
        logError(message)


def logError(message):
    print('[%d] %s' % (os.getpid(), message), file=sys.stderr)


class ChromeGNOMEShell(Gio.Application):
    def __init__(self):
        Gio.Application.__init__(self,
                                    application_id='org.gnome.chrome-gnome-shell-%s' % os.getppid(),
                                    flags=Gio.ApplicationFlags.HANDLES_COMMAND_LINE)

        self.shellAppearedId = None
        self.shellSignalId = None
        self.proxy = Gio.DBusProxy.new_for_bus_sync(Gio.BusType.SESSION,
                                       Gio.DBusProxyFlags.NONE,
                                       None,
                                       'org.gnome.Shell',
                                       '/org/gnome/Shell',
                                       'org.gnome.Shell.Extensions',
                                       None)

        # Set custom exception hook
        sys.excepthook = self.default_exception_hook


    def default_exception_hook(self, type, value, tb):
        logError("Uncaught exception of type %s occured" % type)
        traceback.print_tb(tb)
        logError("Exception: %s" % value)

        self.release()

    def do_startup(self):
        debug('Startup')
        Gio.Application.do_startup(self)


    def do_shutdown(self):
        debug('Shutdown')
        Gio.Application.do_shutdown(self)

        if self.shellAppearedId:
            Gio.bus_unwatch_name(self.shellAppearedId)

        if self.shellSignalId:
            self.proxy.disconnect(self.shellSignalId)


    def do_activate(self, app):
        debug('Activate')
        Gio.Application.do_activate(self)


    def do_local_command_line(self, arguments):
        stdin = GLib.IOChannel.unix_new(sys.stdin.fileno())
        stdin.set_encoding(None)
        stdin.set_buffered(False)

        GLib.unix_signal_add(GLib.PRIORITY_DEFAULT, signal.SIGINT, self.on_sigint, None)
        GLib.io_add_watch(stdin, GLib.PRIORITY_DEFAULT, GLib.IOCondition.IN, self.on_input, None)
        GLib.io_add_watch(stdin, GLib.PRIORITY_DEFAULT, GLib.IOCondition.HUP, self.on_hup, None)
        GLib.io_add_watch(stdin, GLib.PRIORITY_DEFAULT, GLib.IOCondition.ERR, self.on_hup, None)

        self.hold()

        return (True, None, 0)


    def on_input(self, source, condition, data):
        debug('On input')
        text_length_bytes = source.read(MESSAGE_LENGTH_SIZE)

        if len(text_length_bytes) == 0:
            debug('Release condition: %s' % str(condition))
            self.release()
            return

        # Unpack message length as 4 byte integer.
        text_length = struct.unpack(b'i', text_length_bytes)[0]

        # Read the text (JSON object) of the message.
        text = source.read(text_length).decode('utf-8')

        request = json.loads(text)

        if 'execute' in request:
            if 'uuid' in request and not isUUID(request['uuid']):
                return

            self.process_request(request)


    def on_shell_signal(self, d_bus_proxy, sender_name, signal_name, parameters):
        if signal_name == 'ExtensionStatusChanged':
            debug('Signal: to %s' % signal_name)
            self.send_message({'signal': signal_name, 'parameters': parameters.unpack()})
            debug('Signal: from %s' % signal_name)


    def on_shell_appeared(self, connection, name, name_owner):
        debug('Signal: to %s' % name)
        self.send_message({'signal': name})
        debug('Signal: from %s' % name)


    def on_hup(self, source, condition, data):
        debug('On hup: %s' % str(condition))
        self.release()


    def on_sigint(self, data):
        debug('On sigint')
        self.release()


    # Helper function that sends a message to the webapp.
    def send_message(self, response):
        message = json.dumps(response)
        message_length = len(message.encode('utf-8'))

        if message_length > 1024*1024:
            logError('Too long message (%d): "%s"' % (message_length, message))
            return

        try:
            stdout = GLib.IOChannel.unix_new(sys.stdout.fileno())
            stdout.set_encoding(None)
            stdout.set_buffered(False)

            stdout.write_chars(struct.pack(b'I', message_length), MESSAGE_LENGTH_SIZE)

            # Write the message itself.
            stdout.write_chars(message, message_length)
        except IOError as e:
            logError('IOError occured: %s' % e.strerror)
            sys.exit(1)


    def send_error(self, message):
        self.send_message({'success': False, 'message': message})


    def dbus_call_response(self, method, parameters, resultProperty):
        try:
            result = self.proxy.call_sync(method,
                                     parameters,
                                     Gio.DBusCallFlags.NONE,
                                     -1,
                                     None)

            self.send_message({'success': True, resultProperty: result.unpack()[0]})
        except GLib.GError as e:
            self.send_error(e.message)


    def process_request(self, request):
        debug('Execute: to %s' % request['execute'])

        if request['execute'] == 'initialize':
            settings = Gio.Settings.new(SHELL_SCHEMA)
            shellVersion = self.proxy.get_cached_property("ShellVersion")
            if EXTENSION_DISABLE_VERSION_CHECK_KEY in settings.keys():
                disableVersionCheck = settings.get_boolean(EXTENSION_DISABLE_VERSION_CHECK_KEY)
            else:
                disableVersionCheck = False

            self.send_message(
                {
                    'success': True,
                    'properties': {
                        'connectorVersion': CONNECTOR_VERSION,
                        'shellVersion': shellVersion.unpack(),
                        'versionValidationEnabled': not disableVersionCheck
                    }
                }
            )

        elif request['execute'] == 'subscribeSignals':
            if not self.shellAppearedId:
                self.shellAppearedId = Gio.bus_watch_name(Gio.BusType.SESSION,
                                                     'org.gnome.Shell',
                                                     Gio.BusNameWatcherFlags.NONE,
                                                     self.on_shell_appeared,
                                                     None)

            if not self.shellSignalId:
                self.shellSignalId = self.proxy.connect('g-signal', self.on_shell_signal)

        elif request['execute'] == 'installExtension':
            self.dbus_call_response("InstallRemoteExtension",
                               GLib.Variant.new_tuple(GLib.Variant.new_string(request['uuid'])),
                               "status")

        elif request['execute'] == 'listExtensions':
            self.dbus_call_response("ListExtensions", None, "extensions")

        elif request['execute'] == 'enableExtension':
            settings = Gio.Settings.new(SHELL_SCHEMA)
            uuids = settings.get_strv(ENABLED_EXTENSIONS_KEY)

            extensions = []
            if 'extensions' in request:
                extensions = request['extensions']
            else:
                extensions.append({'uuid': request['uuid'], 'enable': request['enable'] })

            for extension in extensions:
                if not isUUID(extension['uuid']):
                    continue

                if extension['enable']:
                    uuids.append(extension['uuid'])
                elif extension['uuid'] in uuids:
                    uuids.remove(extension['uuid'])

            settings.set_strv(ENABLED_EXTENSIONS_KEY, uuids)

            self.send_message({'success': True})

        elif request['execute'] == 'launchExtensionPrefs':
            self.proxy.call("LaunchExtensionPrefs",
                       GLib.Variant.new_tuple(GLib.Variant.new_string(request['uuid'])),
                       Gio.DBusCallFlags.NONE,
                       -1,
                       None,
                       None,
                       None)

        elif request['execute'] == 'getExtensionErrors':
            self.dbus_call_response("GetExtensionErrors",
                               GLib.Variant.new_tuple(GLib.Variant.new_string(request['uuid'])),
                               "extensionErrors")

        elif request['execute'] == 'getExtensionInfo':
            self.dbus_call_response("GetExtensionInfo",
                               GLib.Variant.new_tuple(GLib.Variant.new_string(request['uuid'])),
                               "extensionInfo")

        elif request['execute'] == 'uninstallExtension':
            self.dbus_call_response("UninstallExtension",
                               GLib.Variant.new_tuple(GLib.Variant.new_string(request['uuid'])),
                               "status")

        elif request['execute'] == 'checkUpdate':
            update_url = 'https://extensions.gnome.org/update-info/'
            if 'url' in request:
                update_url = request['url']

            self.check_update(update_url)




        debug('Execute: from %s' % request['execute'])

    def check_update(self, update_url):
        result = self.proxy.call_sync("ListExtensions",
                                 None,
                                 Gio.DBusCallFlags.NONE,
                                 -1,
                                 None)

        extensions = result.unpack()[0]

        if extensions:
            http_request = {
                'shell_version': self.proxy.get_cached_property("ShellVersion").unpack(),
                'installed': {}
            }

            for uuid in extensions:
                if isUUID(uuid):
                    try:
                        http_request['installed'][uuid] = {
                            'version': int(extensions[uuid]['version'])
                        }
                    except ValueError:
                        http_request['installed'][uuid] = {
                            'version': 1
                        }

            http_request['installed'] = json.dumps(http_request['installed'])

            try:
                response = requests.get(
                                        update_url,
                                        params=http_request,
                                        timeout=5
                                        )
                response.raise_for_status()
                self.send_message({
                             'success': True,
                             'extensions': extensions,
                             'upgrade': response.json()}
                             )
            except (
                    requests.ConnectionError, requests.HTTPError, requests.Timeout,
                    requests.TooManyRedirects, requests.RequestException, ValueError
                    ) as ex:
                self.send_message({'success': False, 'message': str(ex.message) if ('message' in ex) else str(ex)})


if __name__ == '__main__':
    debug('Main. Use CTRL+D to quit.')

    app = ChromeGNOMEShell()
    app.register()
    app.run(sys.argv)

    debug('Quit')
