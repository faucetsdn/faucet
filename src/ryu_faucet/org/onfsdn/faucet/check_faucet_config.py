#!/usr/bin/python

import logging
import sys

import valve
from config_parser import dp_parser


def check_config(conf_files):
    logname = '/dev/null'
    logger = logging.getLogger('%s.config' % logname)
    logger_handler = logging.StreamHandler(stream=sys.stderr)
    logger.addHandler(logger_handler)
    logger.propagate = 0
    logger.setLevel(logging.DEBUG)

    for conf_file in conf_files:
        parse_result = dp_parser(conf_file, logname)
        if parse_result is None:
            return False
        else:
            _, dps = parse_result
            for dp in dps:
                valve_dp = valve.valve_factory(dp)
                if valve_dp is None:
                    return False
                print(dp.to_conf())
    return True


if __name__ == '__main__':
    if check_config(sys.argv[1:]):
        sys.exit(0)
    else:
        sys.exit(-1)
