# SPDX-License-Identifer: GPL-3.0-or-later

import logging
from typing import Any

def get_logger(obj: Any):
    return logging.getLogger(".".join((
        obj.__class__.__module__,
        obj.__class__.__qualname__))
    )


class NameAbbrFilter(logging.Filter):
    def filter(self, record: logging.LogRecord):
        modules = record.name.split(".")
        record.name_abbr = ".".join(
            [
                "_".join(
                    p[:1]
                    for p in m.split("_")
                )
                for m in modules[:-1]
            ] +
            [modules[-1]]
        )

        return True
