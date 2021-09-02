#!/usr/bin/env python3

"""Run AFL repeatedly with externally supplied generated config from STDIN."""


import logging
import tempfile
import os
import sys

import afl

from faucet import config_parser as cp
from faucet.conf import InvalidConfigError


ROUNDS = 50000
LOGNAME = 'FAUCET_FUZZER_LOG'
tmpdir = tempfile.mkdtemp()
conf_file_name = os.path.join(tmpdir, 'faucet.yaml')


def create_config_file(config):
    """Create config file with given contents."""
    with open(conf_file_name, 'w', encoding='utf-8') as conf_file:
        conf_file.write(config)
    return conf_file_name


def main():
    """Runs the py-AFL fuzzer with the faucet config parser"""
    logging.disable(logging.CRITICAL)
    while afl.loop(ROUNDS):  # pylint: disable=c-extension-no-member
        config = sys.stdin.read()
        file_name = create_config_file(config)
        try:
            cp.dp_parser(file_name, LOGNAME)
        except InvalidConfigError:
            pass


if __name__ == "__main__":
    main()
