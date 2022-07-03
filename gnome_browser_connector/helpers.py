# SPDX-License-Identifer: GPL-3.0-or-later

import re
from typing import Any

from gi.repository import Gio, GLib

def get_variant(data: Any) -> GLib.Variant:
    if isinstance(data, str):
        return GLib.Variant.new_string(data)
    elif isinstance(data, int):
        return GLib.Variant.new_int32(data)
    elif isinstance(data, (list, tuple, set)):
        variant_builder: GLib.VariantBuilder = GLib.VariantBuilder.new(GLib.VariantType.new('av'))

        for value in data:
            variant_builder.add_value(GLib.Variant.new_variant(self.get_variant(value)))

        return variant_builder.end()
    elif isinstance(data, dict):
        variant_builder = GLib.VariantBuilder.new(GLib.VariantType.new('a{sv}'))

        for key in data:
            if data[key] is None:
                continue

            key_string = str(key)

            variant_builder.add_value(
                GLib.Variant.new_dict_entry(
                    self.get_variant(key_string), GLib.Variant.new_variant(self.get_variant(data[key]))
                )
            )

        return variant_builder.end()
    else:
        raise Exception(f"Unknown data type: {type(data)}")

# https://wiki.gnome.org/Projects/GnomeShell/Extensions/UUIDGuidelines
def is_uuid(uuid: str):
    return uuid is not None and re.match('[-a-zA-Z0-9@._]+$', uuid) is not None

def obtain_gio_settings(schema: str) -> Gio.Settings:
    source: Gio.SettingsSchemaSource = Gio.SettingsSchemaSource.get_default()

    if source is None:
        raise Exception("No Gio.Settings schemas are installed")

    if source.lookup(schema, True) is None:
        raise Exception("Settings schema with id `{schema}` is missing")

    return Gio.Settings.new(schema)
