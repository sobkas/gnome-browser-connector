# SPDX-License-Identifer: GPL-3.0-or-later

import json
from logging import getLogger
import signal
import struct
import sys
import traceback
from types import TracebackType
from typing import Any, Callable, Optional

from gi.repository import GLib, Gio, GObject

from gnome_browser_connector.helpers import get_variant, is_uuid

from .version import __version__


class Application(Gio.Application):
    SHELL_SCHEMA = "org.gnome.shell"
    ENABLED_EXTENSIONS_KEY = "enabled-extensions"
    EXTENSION_DISABLE_VERSION_CHECK_KEY = "disable-extension-version-validation"
    DISABLE_USER_EXTENSIONS_KEY = "disable-user-extensions"

    # https://developer.chrome.com/extensions/nativeMessaging#native-messaging-host-protocol
    MESSAGE_LENGTH_SIZE = 4

    def __init__(self, run_as_service: bool) -> None:
        self.LOG = getLogger(".".join((
            self.__class__.__module__,
            self.__class__.__qualname__))
        )

        self.gio_settings = None
        self.shell_appeared_id = None
        self.shell_signal_id = None
        self.disable_user_extensions_signal_id = None
        self.disable_version_check_signal_id = None

        Gio.Application.__init__(
            self,
            application_id='org.gnome.ChromeGnomeShell',
            flags=(
                Gio.ApplicationFlags.IS_SERVICE if run_as_service
                else Gio.ApplicationFlags.IS_LAUNCHER | Gio.ApplicationFlags.HANDLES_OPEN
            )
        )

        # Set custom exception hook
        sys.excepthook = self.default_exception_hook

        self.register()

        if not run_as_service:
            self.shell_proxy = Gio.DBusProxy.new_sync(
                self.get_dbus_connection2(),
                Gio.DBusProxyFlags.NONE,
                None,
                'org.gnome.Shell',
                '/org/gnome/Shell',
                'org.gnome.Shell.Extensions',
                None
            )

            self.get_dbus_connection2().signal_subscribe(
                self.get_application_id(),
                self.get_application_id(),
                None,
                "/org/gnome/ChromeGnomeShell",
                None,
                Gio.DBusSignalFlags.NONE,
                self.on_dbus_signal,
                None
            )

            stdin = GLib.IOChannel.unix_new(sys.stdin.fileno())
            stdin.set_encoding(None)
            stdin.set_buffered(False)

            GLib.io_add_watch(stdin, GLib.PRIORITY_DEFAULT, GLib.IOCondition.IN, self.on_input, None)
            GLib.io_add_watch(stdin, GLib.PRIORITY_DEFAULT, GLib.IOCondition.HUP, self.on_hup, None)
            GLib.io_add_watch(stdin, GLib.PRIORITY_DEFAULT, GLib.IOCondition.ERR, self.on_hup, None)
        else:
            self.add_simple_action("create-notification", self.on_create_notification, 'a{sv}')
            self.add_simple_action("on-notification-clicked", self.on_notification_clicked, 's')
            self.add_simple_action("on-notification-action", self.on_notification_action, '(si)')

            GLib.timeout_add_seconds(5 * 60, self.on_service_timeout, None)

        GLib.unix_signal_add(GLib.PRIORITY_DEFAULT, signal.SIGINT, self.on_sigint, None)

        if not run_as_service or not self.get_is_remote():
            self.hold()

    def get_dbus_connection2(self) -> Gio.DBusConnection:
        dbus_connection = super().get_dbus_connection()

        if not dbus_connection:
            raise Exception('No DBus connection available')

        return dbus_connection

    # Is there any way to hook this to shutdown?
    def clean_release(self) -> None:
        self.LOG.debug('Releasing resources')

        if self.shell_appeared_id:
            Gio.bus_unwatch_name(self.shell_appeared_id)

        if self.shell_signal_id:
            self.get_dbus_connection2().signal_unsubscribe(self.shell_signal_id)

        if self.disable_user_extensions_signal_id:
            if self.gio_settings is not None:
                self.gio_settings.disconnect(self.disable_user_extensions_signal_id)

        if self.disable_version_check_signal_id:
            if self.gio_settings is not None:
                self.gio_settings.disconnect(self.disable_version_check_signal_id)

        self.release()

    def default_exception_hook(
        self,
        exception_type: type[BaseException],
        value: BaseException,
        tb: TracebackType
    ) -> None:
        self.LOG.fatal("Uncaught exception of type %s occured", exception_type)
        traceback.print_tb(tb)
        self.LOG.fatal("Exception: %s", value)

        self.clean_release()

    def add_simple_action(self, name: str, callback: Callable[..., None], parameter_type: str) -> None:
        action = Gio.SimpleAction.new(
            name,
            GLib.VariantType.new(parameter_type) if parameter_type is not None else None
        )
        action.connect('activate', callback)
        self.add_action(action)

    # Service events
    def on_create_notification(self, source: GObject.Object, request: GLib.Variant) -> None:
        self.LOG.debug('On create notification')

        request = request.unpack()

        notification = Gio.Notification.new(request['title'])
        notification.set_body(request['message'])
        notification.set_priority(Gio.NotificationPriority.NORMAL)
        notification.set_default_action_and_target(
            "app.on-notification-clicked",
            GLib.Variant.new_string(request['name'])
        )

        if 'buttons' in request:
            for button_id, button in enumerate(request['buttons']):
                notification.add_button_with_target(
                    button['title'],
                    "app.on-notification-action",
                    GLib.Variant.new_tuple(
                        GLib.Variant.new_string(request['name']),
                        GLib.Variant.new_int32(button_id)
                    )
                )

        self.send_notification(request['name'], notification)

    def on_notification_action(self, notification: GObject.Object, parameters: GLib.Variant) -> None:
        self.LOG.debug('Notification %s action: %s', *parameters.unpack())

        self.get_dbus_connection2().emit_signal(
            None,
            self.get_dbus_object_path(),
            self.get_application_id(),
            "NotificationAction",
            parameters
        )

    def on_notification_clicked(self, notification: GObject.Object, notification_name: GLib.Variant) -> None:
        self.LOG.debug('Notification %s clicked', notification_name)

        self.get_dbus_connection2().emit_signal(
            None,
            self.get_dbus_object_path(),
            self.get_application_id(),
            "NotificationClicked",
            GLib.Variant.new_tuple(notification_name)
        )

    def on_service_timeout(self, data: Optional[GObject.Object]) -> bool:
        self.LOG.debug('On service timeout')
        self.clean_release()

        return False

    # Native messaging events
    def on_input(
        self,
        source: GLib.IOChannel,
        condition: GLib.IOCondition,
        data: Optional[GObject.Object]
    ) -> Optional[bool]:
        self.LOG.debug('On input')
        text_length_bytes: bytes = source.read(self.MESSAGE_LENGTH_SIZE)

        if len(text_length_bytes) == 0:
            self.LOG.debug('Release condition: %s', condition)
            self.clean_release()
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
        self.LOG.debug('Signal %s from %s', signal_name, interface_name)

        if (
            interface_name == "org.gnome.Shell.Extensions" and
            signal_name == 'ExtensionStatusChanged'
        ):
            self.send_message({'signal': signal_name, 'parameters': parameters.unpack()})
        elif interface_name == self.get_application_id():
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
        self.LOG.debug('Signal: to %s', name)
        self.send_message({'signal': name})
        self.LOG.debug('Signal: from %s', name)

    def on_setting_changed(self, settings: Gio.Settings, key: str) -> None:
        if not key in (self.DISABLE_USER_EXTENSIONS_KEY, self.EXTENSION_DISABLE_VERSION_CHECK_KEY):
            return

        self.LOG.debug('on_setting_changed: %s=%s', key, settings.get_value(key).unpack())
        self.send_message({
            'signal': 'ShellSettingsChanged',
            'key': key,
            'value': settings.get_value(key).unpack()
        })

    # General events
    def on_hup(self, source: GLib.IOChannel, condition: GLib.IOCondition, data: Optional[GLib.Variant]):
        self.LOG.debug('On hup: %s', str(condition))
        self.clean_release()

        return False

    def on_sigint(self, data: Optional[Any]):
        self.LOG.debug('On sigint')
        self.clean_release()

        return False

    # Helpers
    def dbus_call_response(self, method: str, parameters: Optional[GLib.Variant], result_property: str):
        try:
            result = self.shell_proxy.call_sync(method,
                                                parameters,
                                                Gio.DBusCallFlags.NONE,
                                                -1,
                                                None)

            self.send_message({'success': True, result_property: result.unpack()[0]})
        except GLib.GError as e:
            self.send_error(e.message)

    def send_error(self, message: str):
        self.send_message({'success': False, 'message': message})

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

    def obtain_gio_settings(self) -> None:
        if not self.gio_settings:
            source: Gio.SettingsSchemaSource = Gio.SettingsSchemaSource.get_default()

            if source is None:
                raise Exception("No Gio.Settings schemas are installed")

            if source.lookup(self.SHELL_SCHEMA, True) is None:
                raise Exception("GNOME Shell schema with id `{SHELL_SCHEMA}` is missing")

            self.gio_settings: Gio.Settings = Gio.Settings.new(self.SHELL_SCHEMA)

    def set_shell_boolean(self, key: str, value: bool) -> bool:
        self.obtain_gio_settings()
        if key in self.gio_settings.keys():
            return self.gio_settings.set_boolean(key, True if value else False)

        return False

    def process_request(self, request: dict[str, Any]) -> None:
        self.LOG.debug("Execute: to %s", request['execute'])

        if request['execute'] == 'initialize':
            shell_version = self.shell_proxy.get_cached_property("ShellVersion")

            if shell_version is not None:
                self.obtain_gio_settings()

                if self.EXTENSION_DISABLE_VERSION_CHECK_KEY in self.gio_settings.keys():
                    disable_version_check: bool = self.gio_settings.get_boolean(
                        self.EXTENSION_DISABLE_VERSION_CHECK_KEY
                    )
                else:
                    disable_version_check = False

                if self.DISABLE_USER_EXTENSIONS_KEY in self.gio_settings.keys():
                    disable_user_extensions: bool = self.gio_settings.get_boolean(self.DISABLE_USER_EXTENSIONS_KEY)
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
            if not self.shell_appeared_id:
                self.shell_appeared_id = Gio.bus_watch_name_on_connection(
                    self.get_dbus_connection2(),
                    'org.gnome.Shell',
                    Gio.BusNameWatcherFlags.NONE,
                    self.on_shell_appeared,
                    None
                )

            if not self.shell_signal_id:
                self.shell_signal_id = self.get_dbus_connection2().signal_subscribe(
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
                self.obtain_gio_settings()
                self.disable_user_extensions_signal_id = self.gio_settings.connect(
                    f"changed::{self.DISABLE_USER_EXTENSIONS_KEY}",
                    self.on_setting_changed)

            if not self.disable_version_check_signal_id:
                self.obtain_gio_settings()
                self.disable_version_check_signal_id = self.gio_settings.connect(
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
            self.obtain_gio_settings()
            uuids = self.gio_settings.get_strv(self.ENABLED_EXTENSIONS_KEY)

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

            self.gio_settings.set_strv(self.ENABLED_EXTENSIONS_KEY, uuids)

            self.send_message({'success': True})

        elif request['execute'] == 'launchExtensionPrefs':
            self.shell_proxy.call("LaunchExtensionPrefs",
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
                self.get_dbus_connection2(),
                self.get_application_id(),
                self.get_dbus_object_path()
            ).activate_action('create-notification', get_variant({
                'name': request['name'],
                'title': request['options']['title'],
                'message': request['options']['message'],
                'buttons': request['options']['buttons']
            }))

        elif request['execute'] == 'removeNotification':
            self.withdraw_notification(request['name'])

        self.LOG.debug('Execute: from %s',  request['execute'])
