#!/usr/bin/env python3

"""Launch script for Faucet/Gauge.

The command line is unchanged: the ``--ryu-*`` flags and the ``ryu.conf``
file are an operator contract, shipped in the systemd units. What changed is
underneath -- they now configure the OpenFlow listener directly instead of
being translated into oslo.config arguments for an inlined ``osken-manager``.
"""

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

# pylint: disable=wrong-import-position
import os
import sys

# When invoked as ``python /path/to/faucet/__main__.py`` (which is how the
# mininet integration tests start Faucet) Python puts the script's directory
# at ``sys.path[0]``, which shadows the ``faucet`` package with the
# ``faucet/faucet.py`` *submodule*. ``import faucet.valve_ryuapp`` then fails
# with "'faucet' is not a package". Strip every ``sys.path`` entry that
# resolves to the script's directory (CI also explicitly puts
# ``/faucet-src/faucet`` on ``PYTHONPATH`` via ``docker/runtests.sh``, and
# Docker bind-mounts may surface that same dir under aliased paths).
_self_real = os.path.realpath(os.path.dirname(os.path.abspath(__file__)))
sys.path[:] = [_p for _p in sys.path if os.path.realpath(_p) != _self_real]
del _self_real

import argparse
import configparser
import logging
import logging.handlers

from pbr.version import VersionInfo

from c65of import hub
from c65of.app import AppManager
from c65of.controller import OpenFlowController

if sys.version_info < (3, 11):
    raise ImportError(
        """You are trying to run faucet on python {py}

Faucet requires python 3.11 or newer.""".format(
            py=".".join([str(v) for v in sys.version_info[:3]])
        )
    )

# (flag, help) or (flag, help, default). Named for Ryu because that is what
# the systemd units and the integration tests already pass.
RYU_OPTIONAL_ARGS = [
    ("ca-certs", "CA certificates"),
    (
        "config-file",
        """Path to a config file to use. Defaults to
                       /etc/faucet/ryu.conf.""",
        "/etc/faucet/ryu.conf",
    ),
    ("ctl-cert", "controller certificate"),
    ("ctl-privkey", "controller private key"),
    ("default-log-level", "default log level"),
    ("log-dir", "log file directory"),
    ("log-file", "log file name"),
    ("ofp-listen-host", "openflow listen host (default 0.0.0.0)"),
    ("ofp-ssl-listen-port", "openflow ssl listen port (default: 6653)"),
    ("ofp-tcp-listen-port", "openflow tcp listen port (default: 6653)"),
    ("pid-file", "pid file name"),
]

# ryu.conf keys that configure the OpenFlow channel, and the constructor
# argument each one sets.
CONF_KEYS = {
    "echo_request_interval": "echo_request_interval",
    "maximum_unreplied_echo_requests": "max_unreplied_echo_requests",
    "socket_timeout": "socket_timeout",
    "ofp_listen_host": "listen_host",
    "ofp_tcp_listen_port": "tcp_port",
    "ofp_ssl_listen_port": "ssl_port",
}
INT_KEYS = frozenset(
    (
        "echo_request_interval",
        "max_unreplied_echo_requests",
        "socket_timeout",
        "tcp_port",
        "ssl_port",
    )
)


def parse_args(sys_args):
    """Parse Faucet/Gauge arguments.

    Returns:
        argparse.Namespace: command line arguments
    """
    args = argparse.ArgumentParser(prog="faucet", description="Faucet SDN Controller")
    args.add_argument("--gauge", action="store_true", help="run Gauge instead")
    args.add_argument(
        "-v", "--verbose", action="store_true", help="produce verbose output"
    )
    args.add_argument(
        "-V", "--version", action="store_true", help="print version and exit"
    )
    args.add_argument("--use-stderr", action="store_true", help="log to standard error")
    args.add_argument("--use-syslog", action="store_true", help="output to syslog")
    args.add_argument(
        "--ryu-app-lists",
        action="append",
        help="add an application module (can be specified multiple times)",
        metavar="APP",
    )
    for ryu_arg in RYU_OPTIONAL_ARGS:
        if len(ryu_arg) >= 3:
            args.add_argument(
                "--ryu-%s" % ryu_arg[0], help=ryu_arg[1], default=ryu_arg[2]
            )
        else:
            args.add_argument("--ryu-%s" % ryu_arg[0], help=ryu_arg[1])
    return args.parse_args(sys_args)


def print_version():
    """Print version number and exit."""
    version = VersionInfo("c65faucet").semantic_version().release_string()
    print("c65faucet %s" % version)


def channel_settings(args):
    """Merge ryu.conf and the command line into OpenFlowController arguments.

    The file supplies the defaults; an explicit flag wins. The file is the
    same ``[DEFAULT]`` INI oslo.config read, so operators' existing
    ``ryu.conf`` keeps working.
    """
    settings = {}
    conf_file = args.ryu_config_file
    if conf_file and os.path.isfile(conf_file):
        parser = configparser.ConfigParser()
        parser.read(conf_file)
        for key, value in parser.defaults().items():
            target = CONF_KEYS.get(key.replace("-", "_"))
            if target:
                settings[target] = value
    for key, target in CONF_KEYS.items():
        value = getattr(args, "ryu_%s" % key, None)
        if value:
            settings[target] = value
    for key in INT_KEYS & set(settings):
        settings[key] = int(settings[key])
    for name, arg in (
        ("ctl_cert", "ryu_ctl_cert"),
        ("ctl_privkey", "ryu_ctl_privkey"),
        ("ca_certs", "ryu_ca_certs"),
    ):
        value = getattr(args, arg, None)
        if value:
            settings[name] = value
    return settings


def init_logging(args):
    """Configure the root logger from the command line."""
    level = logging.DEBUG if args.verbose else logging.INFO
    if args.ryu_default_log_level:
        level = int(args.ryu_default_log_level)
    handlers = []
    if args.use_stderr:
        handlers.append(logging.StreamHandler(sys.stderr))
    if args.use_syslog:
        handlers.append(logging.handlers.SysLogHandler(address="/dev/log"))
    log_file = args.ryu_log_file
    if log_file:
        if args.ryu_log_dir:
            log_file = os.path.join(args.ryu_log_dir, log_file)
        handlers.append(logging.FileHandler(log_file))
    logging.basicConfig(
        level=level,
        handlers=handlers or None,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )


def app_lists(args, prog):
    """The application modules to run, in start order.

    The OpenFlow listener goes last: applications start in this order, and a
    switch that connects before faucet has read its configuration is an
    unknown datapath and gets its channel dropped.
    """
    if args.gauge or os.path.basename(prog) == "gauge":
        apps = ["faucet.gauge"]
    else:
        apps = ["faucet.faucet"]
    if args.ryu_app_lists:
        apps.extend(args.ryu_app_lists)
    apps.append("c65of.controller")
    return apps


def write_pid_file(path):
    """Record this process's pid, if asked to."""
    if path:
        with open(path, "w", encoding="utf-8") as pid_file:
            pid_file.write(str(os.getpid()))


def main():
    """Main program."""
    args = parse_args(sys.argv[1:])
    if args.version:
        print_version()
        return
    init_logging(args)
    write_pid_file(args.ryu_pid_file)

    controller = OpenFlowController(**channel_settings(args))
    manager = AppManager.get_instance()
    manager.load_apps(app_lists(args, sys.argv[0]))
    contexts = manager.create_contexts()
    services = manager.instantiate_apps(controller=controller, **contexts)
    try:
        hub.joinall(services)
    except KeyboardInterrupt:
        logging.getLogger(__name__).debug("keyboard interrupt, shutting down")
    finally:
        manager.close()


if __name__ == "__main__":
    main()
