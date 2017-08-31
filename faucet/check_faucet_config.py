#!/usr/bin/env python

"""Standalone script to check FAUCET configuration, return 0 if provided config OK."""

# Copyright (C) 2015 Brad Cowie, Christopher Lorier and Joe Stringer.
# Copyright (C) 2015 Research and Education Advanced Network New Zealand Ltd.
# Copyright (C) 2015--2017 The Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
import sys

try:
    import valve
    from config_parser import dp_parser
except ImportError:
    from faucet import valve
    from faucet.config_parser import dp_parser


def check_config(conf_files):
    """Check a list of FAUCET YAML config files, return 0 if all are valid."""
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
            _, valve_dps = parse_result
            for valve_dp in valve_dps:
                valve_dp = valve.valve_factory(valve_dp)
                if valve_dp is None:
                    return False
                print((valve_dp.to_conf()))
    return True


def main():
    if check_config(sys.argv[1:]):
        sys.exit(0)
    sys.exit(-1)


if __name__ == '__main__':
    main()
