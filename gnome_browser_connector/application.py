# SPDX-License-Identifer: GPL-3.0-or-later

from __future__ import annotations

import signal
import sys
import traceback
from types import TracebackType
from typing import Any, Callable, Optional, Sequence

from gi.repository import GLib, Gio

from gnome_browser_connector.constants import CONNECTOR_ARG
from gnome_browser_connector.helpers import is_uuid

from .base import BaseGioApplication
from .logs import get_logger
from .connector import Connector
from .service import Service


class Application(BaseGioApplication):
    def __init__(self) -> None:
        Gio.Application.__init__(
            self,
            application_id='org.gnome.BrowserConnector',
            flags=Gio.ApplicationFlags.HANDLES_OPEN
        )

        self._log = get_logger(self)
        self._handler = None

        # Set custom exception hook
        sys.excepthook = self.default_exception_hook

        self.add_main_option(
            CONNECTOR_ARG,
            ord(CONNECTOR_ARG[:1]),
            GLib.OptionFlags.NONE,
            GLib.OptionArg.NONE,
            "Run as browser messaging host"
        )

        GLib.unix_signal_add(GLib.PRIORITY_DEFAULT, signal.SIGINT, self.on_sigint, None)

        self._stdin: GLib.IOChannel = GLib.IOChannel.unix_new(sys.stdin.fileno())
        self._stdin.set_encoding(None)
        self._stdin.set_buffered(False)

        self.stdin_add_watch(GLib.PRIORITY_DEFAULT, GLib.IOCondition.HUP, self.on_hup, None)
        self.stdin_add_watch(GLib.PRIORITY_DEFAULT, GLib.IOCondition.ERR, self.on_hup, None)

    def do_activate(self) -> None:
        pass

    def do_handle_local_options(self, options: GLib.VariantDict):
        is_service = (self.get_flags() & Gio.ApplicationFlags.IS_SERVICE).real
        if not is_service:
            self.set_flags(self.get_flags() | Gio.ApplicationFlags.IS_LAUNCHER)

        self.register()

        if is_service:
            self._handler = Service(self)
        elif options.contains(CONNECTOR_ARG):
            self._handler = Connector(self)

        return -1

    def do_open(self, files: Sequence[Gio.File], n_files: int, hint: str):
        for file in files:
            if file.get_uri_scheme() != 'gnome-extensions':
                continue

            uri: GLib.Uri = GLib.uri_parse(file.get_uri(), GLib.UriFlags.NON_DNS)
            uuid = uri.get_host()
            if not is_uuid(uuid):
                self._log.fatal(f"Wrong extension UUID passed: `{uuid}`")
                continue

            params = GLib.Uri.parse_params(uri.get_query(), -1, "&", GLib.UriParamsFlags.NONE)
            if 'action' in params:
                if params['action'] == 'install':
                    try:
                        Gio.DBusProxy.new_sync(
                            self.get_dbus_connection2(),
                            Gio.DBusProxyFlags.NONE,
                            None,
                            'org.gnome.Shell',
                            '/org/gnome/Shell',
                            'org.gnome.Shell.Extensions',
                            None
                        ).call_sync(
                            'InstallRemoteExtension',
                            GLib.Variant.new_tuple(GLib.Variant.new_string(uuid)),
                            Gio.DBusCallFlags.NONE,
                            -1,
                            None)
                    except GLib.GError as e:
                        self._log.fatal(f"Unable to install extension: {e.message}")
                        continue

    def stdin_add_watch(
        self,
        priority: int,
        condition: GLib.IOCondition,
        callback: Callable[[GLib.IOChannel, GLib.IOCondition, Optional[GLib.Variant]], None],
        user_data: Optional[GLib.Variant] = None
    ) -> None:
        GLib.io_add_watch(self._stdin, priority, condition, callback, None)

    # Is there any way to hook this to shutdown?
    def clean_resources(self) -> None:
        self._log.debug('Releasing resources')

        if self._handler:
            self._handler.clean_resources()

        self.release()

    def default_exception_hook(
        self,
        exception_type: type[BaseException],
        value: BaseException,
        tb: TracebackType
    ) -> None:
        self._log.fatal("Uncaught exception of type %s occured", exception_type)
        traceback.print_tb(tb)
        self._log.fatal("Exception: %s", value)

        self.clean_resources()

    # General events
    def on_hup(self, source: GLib.IOChannel, condition: GLib.IOCondition, data: Optional[GLib.Variant]):
        self._log.debug('On hup: %s', str(condition))
        self.clean_resources()

        return False

    def on_sigint(self, data: Optional[Any]):
        self._log.debug('On sigint')
        self.clean_resources()

        return False
