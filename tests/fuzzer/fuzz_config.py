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

import afl
while afl.loop(500):
    data = sys.stdin.read()
    file_name = create_config_file(data)
    try:
        cp.dp_parser(file_name, LOGNAME)
    except cp.InvalidConfigError as err:
        pass
os._exit(0)