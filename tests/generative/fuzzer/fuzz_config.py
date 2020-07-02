#!/usr/bin/env python3

"""Run AFL repeatedly with externally supplied generated config from STDIN."""


import logging
import tempfile
import os
import sys

import afl
from faucet import config_parser as cp

ROUNDS = 500
LOGNAME = 'FAUCETLOG'


def create_config_file(config):
    """Create config file with given contents."""
    tmpdir = tempfile.mkdtemp()
    conf_file_name = os.path.join(tmpdir, 'faucet.yaml')
    with open(conf_file_name, 'w') as conf_file:
        conf_file.write(config)
    return conf_file_name


def main():
    logging.disable(logging.CRITICAL)
    while afl.loop(ROUNDS):  # pylint: disable=c-extension-no-member
        config = sys.stdin.read()
        file_name = create_config_file(config)
        try:
            cp.dp_parser(file_name, LOGNAME)
        except cp.InvalidConfigError:
            pass


if __name__ == "__main__":
    main()
