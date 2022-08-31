# SPDX-License-Identifer: GPL-3.0-or-later

from __future__ import annotations

import json
import struct
import sys
from typing import Any, Optional
from gi.repository import Gio, GLib, GObject

from .base import ApplicationHandler, BaseGioApplication
from .helpers import get_variant, is_uuid, obtain_gio_settings
from .logs import get_logger
from .version import __version__

SHELL_SCHEMA = "org.gnome.shell"


class Connector(ApplicationHandler):
    ENABLED_EXTENSIONS_KEY = "enabled-extensions"
    EXTENSION_DISABLE_VERSION_CHECK_KEY = "disable-extension-version-validation"
    DISABLE_USER_EXTENSIONS_KEY = "disable-user-extensions"

    # https://developer.chrome.com/extensions/nativeMessaging#native-messaging-host-protocol
    MESSAGE_LENGTH_SIZE = 4

    def __init__(self, application: BaseGioApplication) -> None:
        super().__init__(application)

        self._log = get_logger(self)
        self._application = application

        self._shell_appeared_id = 0
        self._shell_signal_id = 0
        self.disable_user_extensions_signal_id = None
        self.disable_version_check_signal_id = None

        self._shell_proxy = Gio.DBusProxy.new_sync(
            self._application.get_dbus_connection2(),
            Gio.DBusProxyFlags.NONE,
            None,
            'org.gnome.Shell',
            '/org/gnome/Shell',
            'org.gnome.Shell.Extensions',
            None
        )
        self._shell_settings = obtain_gio_settings(SHELL_SCHEMA)

        self._application.get_dbus_connection2().signal_subscribe(
            self._application.get_application_id(),
            self._application.get_application_id(),
            None,
            "/org/gnome/BrowserConnector",
            None,
            Gio.DBusSignalFlags.NONE,
            self.on_dbus_signal,
            None
        )

        self._application.stdin_add_watch(GLib.PRIORITY_DEFAULT, GLib.IOCondition.IN, self.on_input, None)

        self._application.hold()

        self._log.debug("Messaging host started")

    def clean_resources(self) -> None:
        self._log.debug('Releasing resources')

        if self._shell_appeared_id:
            Gio.bus_unwatch_name(self._shell_appeared_id)

        if self._shell_signal_id:
            self._application.get_dbus_connection2().signal_unsubscribe(self._shell_signal_id)

        if self.disable_user_extensions_signal_id:
            if self._shell_settings is not None:
                self._shell_settings.disconnect(self.disable_user_extensions_signal_id)

        if self.disable_version_check_signal_id:
            if self._shell_settings is not None:
                self._shell_settings.disconnect(self.disable_version_check_signal_id)

    def on_dbus_signal(
        self,
        connection: Gio.DBusConnection,
        sender_name: Optional[str],
        object_path: str,
        interface_name: str,
        signal_name: str,
        parameters: GLib.Variant,
        user_data: Optional[Any]
    ) -> None:
        self._log.debug('Signal %s from %s', signal_name, interface_name)

        if (
            interface_name == "org.gnome.Shell.Extensions" and
            signal_name == 'ExtensionStatusChanged'
        ):
            self.send_message({'signal': signal_name, 'parameters': parameters.unpack()})
        elif interface_name == self._application.get_application_id():
            if signal_name == 'NotificationAction':
                notification_name, button_id = parameters.unpack()

                self.send_message({
                    'signal': "NotificationAction",
                    'name': notification_name,
                    'button_id': button_id
                })
            elif signal_name == 'NotificationClicked':
                (notification_name,) = parameters.unpack()

                self.send_message({
                    'signal': "NotificationClicked",
                    'name': notification_name
                })

    def on_shell_appeared(
        self,
        connection: Gio.DBusConnection,
        name: str,
        name_owner: str
    ) -> None:
        self._log.debug('Signal: to %s', name)
        self.send_message({'signal': name})
        self._log.debug('Signal: from %s', name)

    def on_setting_changed(self, settings: Gio.Settings, key: str) -> None:
        if not key in (self.DISABLE_USER_EXTENSIONS_KEY, self.EXTENSION_DISABLE_VERSION_CHECK_KEY):
            return

        self._log.debug('on_setting_changed: %s=%s', key, settings.get_value(key).unpack())
        self.send_message({
            'signal': 'ShellSettingsChanged',
            'key': key,
            'value': settings.get_value(key).unpack()
        })

    # Native messaging events
    def on_input(
        self,
        source: GLib.IOChannel,
        condition: GLib.IOCondition,
        data: Optional[GObject.Object]
    ) -> Optional[bool]:
        self._log.debug('On input')
        text_length_bytes: bytes = source.read(self.MESSAGE_LENGTH_SIZE)

        if len(text_length_bytes) == 0:
            self._log.debug('Release condition: %s', condition)
            self._application.clean_resources()
            return

        # Unpack message length as 4 byte integer.
        text_length = struct.unpack(b'i', text_length_bytes)[0]

        # Read the text (JSON object) of the message.
        text: str = source.read(text_length).decode('utf-8')

        request = json.loads(text)

        if 'execute' in request:
            if 'uuid' in request and not is_uuid(request['uuid']):
                return

            self.process_request(request)

        return True

    def send_message(self, response: Any):
        """
        Helper function that sends a message to the webapp.
        :param response: dictionary of response data
        :return: None
        """

        message = json.dumps(response)
        message_length = len(message.encode('utf-8'))

        if message_length > 1024*1024:
            raise Exception(f'Too long message ({message_length}): "{message}"')

        try:
            stdout: GLib.IOChannel = GLib.IOChannel.unix_new(sys.stdout.fileno())
            stdout.set_encoding(None)
            stdout.set_buffered(False)

            stdout.write_chars(struct.pack(b'I', message_length), self.MESSAGE_LENGTH_SIZE)

            # Write the message itself.
            stdout.write_chars(message.encode('utf-8'), message_length)
        except IOError as e:
            raise Exception(f'IOError occured: {e.strerror}')

    def process_request(self, request: dict[str, Any]) -> None:
        self._log.debug("Execute: to %s", request['execute'])

        if request['execute'] == 'initialize':
            shell_version = self._shell_proxy.get_cached_property("ShellVersion")

            if shell_version is not None:
                if self.EXTENSION_DISABLE_VERSION_CHECK_KEY in self._shell_settings.keys():
                    disable_version_check: bool = self._shell_settings.get_boolean(
                        self.EXTENSION_DISABLE_VERSION_CHECK_KEY
                    )
                else:
                    disable_version_check = False

                if self.DISABLE_USER_EXTENSIONS_KEY in self._shell_settings.keys():
                    disable_user_extensions: bool = self._shell_settings.get_boolean(self.DISABLE_USER_EXTENSIONS_KEY)
                else:
                    disable_user_extensions = False

                supports = ['notifications', 'v6']

                self.send_message(
                    {
                        'success': True,
                        'properties': {
                            'connectorVersion': __version__,
                            'shellVersion': shell_version.unpack(),
                            'versionValidationEnabled': not disable_version_check,
                            'userExtensionsDisabled': disable_user_extensions,
                            'supports': supports
                        }
                    }
                )
            else:
                self.send_message(
                    {
                        'success': False,
                        'message': "no_gnome_shell"
                    }
                )

        elif request['execute'] == 'subscribeSignals':
            if not self._shell_appeared_id:
                self._shell_appeared_id: int = Gio.bus_watch_name_on_connection(
                    self._application.get_dbus_connection2(),
                    'org.gnome.Shell',
                    Gio.BusNameWatcherFlags.NONE,
                    self.on_shell_appeared,
                    None
                )

            if not self._shell_signal_id:
                self._shell_signal_id: int = self._application.get_dbus_connection2().signal_subscribe(
                    "org.gnome.Shell",
                    "org.gnome.Shell.Extensions",
                    "ExtensionStatusChanged",
                    "/org/gnome/Shell",
                    None,
                    Gio.DBusSignalFlags.NONE,
                    self.on_dbus_signal,
                    None
                )

            if not self.disable_user_extensions_signal_id:
                self.disable_user_extensions_signal_id = self._shell_settings.connect(
                    f"changed::{self.DISABLE_USER_EXTENSIONS_KEY}",
                    self.on_setting_changed)

            if not self.disable_version_check_signal_id:
                self.disable_version_check_signal_id = self._shell_settings.connect(
                    f"changed::{self.EXTENSION_DISABLE_VERSION_CHECK_KEY}",
                    self.on_setting_changed)

        elif request['execute'] == 'installExtension':
            self.dbus_call_response(
                "InstallRemoteExtension",
                GLib.Variant.new_tuple(GLib.Variant.new_string(request['uuid'])),
                "status"
            )

        elif request['execute'] == 'listExtensions':
            self.dbus_call_response("ListExtensions", None, "extensions")

        elif request['execute'] == 'enableExtension':
            uuids = self._shell_settings.get_strv(self.ENABLED_EXTENSIONS_KEY)

            extensions = []
            if 'extensions' in request:
                extensions = request['extensions']
            else:
                extensions.append({'uuid': request['uuid'], 'enable': request['enable']})

            for extension in extensions:
                if not is_uuid(extension['uuid']):
                    continue

                if extension['enable']:
                    if not extension['uuid'] in uuids:
                        uuids.append(extension['uuid'])
                elif extension['uuid'] in uuids:
                    uuids = [value for value in uuids if value != extension['uuid']]

            self._shell_settings.set_strv(self.ENABLED_EXTENSIONS_KEY, uuids)

            self.send_message({'success': True})

        elif request['execute'] == 'launchExtensionPrefs':
            self._shell_proxy.call("LaunchExtensionPrefs",
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

        elif request['execute'] == 'setUserExtensionsDisabled':
            self.send_message({
                'success': self.set_shell_boolean(
                    self.DISABLE_USER_EXTENSIONS_KEY,
                    request['disable']
                )
            })

        elif request['execute'] == 'setVersionValidationDisabled':
            self.send_message({
                'success': self.set_shell_boolean(
                    self.EXTENSION_DISABLE_VERSION_CHECK_KEY,
                    request['disable']
                )
            })

        elif request['execute'] == 'createNotification':
            Gio.DBusActionGroup.get(
                self._application.get_dbus_connection2(),
                self._application.get_application_id(),
                self._application.get_dbus_object_path()
            ).activate_action('create-notification', get_variant({
                'name': request['name'],
                'title': request['options']['title'],
                'message': request['options']['message'],
                'buttons': request['options']['buttons']
            }))

        elif request['execute'] == 'removeNotification':
            self._application.withdraw_notification(request['name'])

        self._log.debug('Execute: from %s',  request['execute'])

    # Helpers
    def dbus_call_response(self, method: str, parameters: Optional[GLib.Variant], result_property: str):
        try:
            result = self._shell_proxy.call_sync(method,
                                                parameters,
                                                Gio.DBusCallFlags.NONE,
                                                -1,
                                                None)

            self.send_message({'success': True, result_property: result.unpack()[0]})
        except GLib.GError as e:
            self.send_error(e.message)

    def send_error(self, message: str):
        self.send_message({'success': False, 'message': message})

    def set_shell_boolean(self, key: str, value: bool) -> bool:
        if key in self._shell_settings.keys():
            return self._shell_settings.set_boolean(key, True if value else False)

        return False
