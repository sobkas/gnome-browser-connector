# SPDX-License-Identifer: GPL-3.0-or-later

from typing import Callable, Optional

from gi.repository import Gio, GLib, GObject

from .base import ApplicationHandler, BaseGioApplication
from .logs import get_logger


class Service(ApplicationHandler):
    def __init__(self, application: BaseGioApplication) -> None:
        if application.get_is_remote():
            return

        super().__init__(application)

        self._log = get_logger(self)
        self._application = application

        self.add_simple_action("create-notification", self.on_create_notification, 'a{sv}')
        self.add_simple_action("on-notification-clicked", self.on_notification_clicked, 's')
        self.add_simple_action("on-notification-action", self.on_notification_action, '(si)')

        GLib.timeout_add_seconds(5 * 60, self.on_service_timeout, None)

        self._application.hold()

        self._log.debug("Service started")

    def clean_resources(self) -> None:
        pass

    def add_simple_action(self, name: str, callback: Callable[..., None], parameter_type: str) -> None:
        action = Gio.SimpleAction.new(
            name,
            GLib.VariantType.new(parameter_type) if parameter_type is not None else None
        )
        action.connect('activate', callback)
        self._application.add_action(action)

    # Service events
    def on_create_notification(self, source: GObject.Object, request: GLib.Variant) -> None:
        self._log.debug('On create notification')

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

        self._application.send_notification(request['name'], notification)

    def on_notification_action(self, notification: GObject.Object, parameters: GLib.Variant) -> None:
        self._log.debug('Notification %s action: %s', *parameters.unpack())

        self._application.get_dbus_connection2().emit_signal(
            None,
            self._application.get_dbus_object_path(),
            self._application.get_application_id(),
            "NotificationAction",
            parameters
        )

    def on_notification_clicked(self, notification: GObject.Object, notification_name: GLib.Variant) -> None:
        self._log.debug('Notification %s clicked', notification_name)

        self._application.get_dbus_connection2().emit_signal(
            None,
            self._application.get_dbus_object_path(),
            self._application.get_application_id(),
            "NotificationClicked",
            GLib.Variant.new_tuple(notification_name)
        )

    def on_service_timeout(self, data: Optional[GObject.Object]) -> bool:
        self._log.debug('On service timeout')
        self._application.clean_resources()

        return False
