# SPDX-License-Identifer: GPL-3.0-or-later

from __future__ import absolute_import

import logging
import os
import sys

from .application import Application
from .constants import CONNECTOR_ARG
from .logs import NameAbbrFilter

def main():
    logging.basicConfig(
        format="%(asctime)s: [%(process)d] %(levelname)s %(name_abbr)s %(message)s",
        level=getattr(
            logging,
            os.getenv("GNOME_BROWSER_CONNECTOR_LOGLEVEL", "warning").upper()
        ),
        stream=sys.stderr
    )
    logging.getLogger().handlers[0].addFilter(NameAbbrFilter())
    logging.debug('Main')

    app = Application()
    code = app.run(sys.argv)

    logging.debug('Quit')

    return code

def connector():
    ensure_argument_exists(CONNECTOR_ARG)
    return main()

def ensure_argument_exists(argument: str):
    if f"--{argument}" not in sys.argv:
        sys.argv.insert(1, f"--{argument}")
