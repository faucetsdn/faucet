#!/usr/bin/env python3

"""Run AFL repeatedly with externally supplied generated config from STDIN."""


import logging
import tempfile
import os
import sys

from faucet import config_parser as cp
from faucet.conf import InvalidConfigError

import afl


ROUNDS = 50000
LOGNAME = 'FAUCET_FUZZER_LOG'
TMPDIR = tempfile.mkdtemp()
CONF_FILE_NAME = os.path.join(TMPDIR, 'faucet.yaml')


def create_config_file(config):
    """Create config file with given contents."""
    with open(CONF_FILE_NAME, 'w') as conf_file:
        conf_file.write(config)
    return CONF_FILE_NAME


def main():
    """Runs the py-AFL fuzzer with the faucet config parser"""
    logging.disable(logging.CRITICAL)
    while afl.loop(ROUNDS):  # pylint: disable=c-extension-no-member
        config = sys.stdin.read()
        file_name = create_config_file(config)
        with open(file_name, 'r'):
            try:
                cp.dp_parser(file_name, LOGNAME)
            except InvalidConfigError:
                pass


if __name__ == "__main__":
    main()
