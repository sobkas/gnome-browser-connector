# SPDX-License-Identifer: GPL-3.0-or-later

from abc import ABC, ABCMeta, abstractmethod
from typing import Callable, Optional

from gi.repository import Gio, GLib


class BaseMeta(ABCMeta, type(Gio.Application)):
    pass


class Cleanable(ABC):
    @abstractmethod
    def clean_resources(self) -> None:
        pass


class BaseGioApplication(Cleanable, Gio.Application, metaclass=BaseMeta):
    def get_dbus_connection2(self) -> Gio.DBusConnection:
        dbus_connection = super().get_dbus_connection()

        if not dbus_connection:
            raise Exception('No DBus connection available')

        return dbus_connection

    def stdin_add_watch(
        self,
        priority: int,
        condition: GLib.IOCondition,
        callback: Callable[[GLib.IOChannel, GLib.IOCondition, Optional[GLib.Variant]], None],
        user_data: Optional[GLib.Variant] = None
    ) -> None:
        pass


class ApplicationHandler(Cleanable):
    @abstractmethod
    def __init__(self, application: BaseGioApplication) -> None:
        pass
