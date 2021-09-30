#!/usr/bin/env python3

"""Launch forwarder script for Faucet/Gauge"""

# Copyright (C) 2015 Brad Cowie, Christopher Lorier and Joe Stringer.
# Copyright (C) 2015 Research and Education Advanced Network New Zealand Ltd.
# Copyright (C) 2015--2019 The Contributors
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

import argparse
import os
import sys

from pbr.version import VersionInfo

if sys.version_info < (3,) or sys.version_info < (3, 6):
    raise ImportError("""You are trying to run faucet on python {py}

Faucet is not compatible with python {py}, please upgrade to python 3.6 or newer."""
                      .format(py='.'.join([str(v) for v in sys.version_info[:3]])))

RYU_OPTIONAL_ARGS = [
    ('ca-certs', 'CA certificates'),
    ('config-dir', """Path to a config directory to pull `*.conf` files
                      from. This file set is sorted, so as to provide a
                      predictable parse order if individual options are
                      over-ridden. The set is parsed after the file(s)
                      specified via previous --config-file, arguments hence
                      over-ridden options in the directory take precedence."""),
    ('config-file', """Path to a config file to use. Multiple config files
                       can be specified, with values in later files taking
                       precedence. Defaults to None.""", "/etc/faucet/ryu.conf"),
    ('ctl-cert', 'controller certificate'),
    ('ctl-privkey', 'controller private key'),
    ('default-log-level', 'default log level'),
    ('log-config-file', 'Path to a logging config file to use'),
    ('log-dir', 'log file directory'),
    ('log-file', 'log file name'),
    ('log-file-mode', 'default log file permission'),
    ('observe-links', 'observe link discovery events'),
    ('ofp-listen-host', 'openflow listen host (default 0.0.0.0)'),
    ('ofp-ssl-listen-port', 'openflow ssl listen port (default: 6653)'),
    ('ofp-switch-address-list', """list of IP address and port pairs (default empty).
                                   e.g., "127.0.0.1:6653,[::1]:6653"""),
    ('ofp-switch-connect-interval', 'interval in seconds to connect to switches (default 1)'),
    ('ofp-tcp-listen-port', 'openflow tcp listen port (default: 6653)'),
    ('pid-file', 'pid file name'),
    ('user-flags', 'Additional flags file for user applications'),
    ('wsapi-host', 'webapp listen host (default 0.0.0.0)'),
    ('wsapi-port', 'webapp listen port (default 8080)')
]


def parse_args(sys_args):
    """Parse Faucet/Gauge arguments.

    Returns:
        argparse.Namespace: command line arguments
    """

    args = argparse.ArgumentParser(
        prog='faucet', description='Faucet SDN Controller')
    args.add_argument('--gauge', action='store_true', help='run Gauge instead')
    args.add_argument(
        '-v', '--verbose', action='store_true', help='produce verbose output')
    args.add_argument(
        '-V', '--version', action='store_true', help='print version and exit')
    args.add_argument(
        '--use-stderr', action='store_true', help='log to standard error')
    args.add_argument(
        '--use-syslog', action='store_true', help='output to syslog')
    args.add_argument(
        '--ryu-app',
        action='append',
        help='add Ryu app (can be specified multiple times)',
        metavar='APP')

    for ryu_arg in RYU_OPTIONAL_ARGS:
        if len(ryu_arg) >= 3:
            args.add_argument(
                f'--ryu-{ryu_arg[0]}',
                help=ryu_arg[1],
                default=ryu_arg[2])
        else:
            args.add_argument(
                f'--ryu-{ryu_arg[0]}',
                help=ryu_arg[1])

    return args.parse_args(sys_args)


def print_version():
    """Print version number and exit."""
    version = VersionInfo('c65faucet').semantic_version().release_string()
    message = 'c65faucet %s' % version
    print(message)


def build_ryu_args(argv):
    args = parse_args(argv[1:])

    # Checking version number?
    if args.version:
        print_version()
        return []

    prog = os.path.basename(argv[0])
    ryu_args = []

    # Handle log location
    if args.use_stderr:
        ryu_args.append('--use-stderr')
    if args.use_syslog:
        ryu_args.append('--use-syslog')

    # Verbose output?
    if args.verbose:
        ryu_args.append('--verbose')

    for arg, val in vars(args).items():
        if not val or not arg.startswith('ryu'):
            continue
        if arg == 'ryu_app':
            continue
        if arg == 'ryu_config_file' and not os.path.isfile(val):
            continue
        arg_name = arg.replace('ryu_', '').replace('_', '-')
        ryu_args.append(f'--{arg_name}={val}')

    # Running Faucet or Gauge?
    if args.gauge or os.path.basename(prog) == 'gauge':
        ryu_args.append('faucet.gauge')
    else:
        ryu_args.append('faucet.faucet')

    # Check for additional Ryu apps.
    if args.ryu_app:
        ryu_args.extend(args.ryu_app)

    # Replace current process with ryu-manager from PATH (no PID change).
    ryu_args.insert(0, 'ryu-manager')
    return ryu_args


def main():
    """Main program."""
    ryu_args = build_ryu_args(sys.argv)
    if ryu_args:
        os.execvp(ryu_args[0], ryu_args)


if __name__ == '__main__':
    main()
