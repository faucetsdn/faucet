#!/usr/bin/env python3

import logging
import tempfile
import os
import sys
from faucet import config_parser as cp

LOGNAME = 'FAUCETLOG'

logging.disable(logging.CRITICAL)
tmpdir = tempfile.mkdtemp()

def create_config_file(config):
    conf_file_name = os.path.join(tmpdir, 'faucet.yaml')
    with open(conf_file_name, 'w') as conf_file:
        conf_file.write(config)
    return conf_file_name

def main():
    s = sys.stdin.read()
    file_name = create_config_file(s)
    try:
        cp.dp_parser(file_name, LOGNAME)
    except cp.InvalidConfigError as err:
        pass

if __name__ == '__main__':
    import afl
    afl.init()
    main()

os._exit(0)