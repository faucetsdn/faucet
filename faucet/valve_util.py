"""Utility functions for FAUCET."""

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
from logging.handlers import WatchedFileHandler
import os
import signal
import sys
from functools import wraps


def kill_on_exception(logname):
    """decorator to ensure functions will kill ryu when an unhandled exception
    occurs"""
    def _koe(func):
        @wraps(func)
        def __koe(*args, **kwargs):
            try:
                func(*args, **kwargs)
            except:
                logging.getLogger(logname).exception(
                    'Unhandled exception, killing RYU')
                logging.shutdown()
                os.kill(os.getpid(), signal.SIGTERM)
        return __koe
    return _koe


def get_sys_prefix():
    """Returns an additional prefix for log and configuration files when used in
    a virtual environment"""

    # Find the appropriate prefix for config and log file default locations
    # in case Faucet is run in a virtual environment. virtualenv marks the
    # original path in sys.real_prefix. If this value exists, and is
    # different from sys.prefix, then we are most likely running in a
    # virtualenv. Also check for Py3.3+ pyvenv.
    sysprefix = ''
    if (getattr(sys, 'real_prefix', sys.prefix) != sys.prefix or
            getattr(sys, 'base_prefix', sys.prefix) != sys.prefix):
        sysprefix = sys.prefix

    return sysprefix


_PREFIX = get_sys_prefix()
DEFAULTS = {
    'FAUCET_CONFIG': _PREFIX + '/etc/ryu/faucet/faucet.yaml',
    'FAUCET_LOG_LEVEL': 'INFO',
    'FAUCET_LOG': _PREFIX + '/var/log/ryu/faucet/faucet.log',
    'FAUCET_EXCEPTION_LOG': _PREFIX + '/var/log/ryu/faucet/faucet_exception.log',
    'FAUCET_PROMETHEUS_PORT': '9302',
    'FAUCET_PROMETHEUS_ADDR': '',
    'FAUCET_PIPELINE_DIR': _PREFIX + '/etc/ryu/faucet',
    'GAUGE_CONFIG': _PREFIX + '/etc/ryu/faucet/gauge.yaml',
    'GAUGE_LOG_LEVEL': 'INFO',
    'GAUGE_EXCEPTION_LOG': _PREFIX + '/var/log/ryu/faucet/gauge_exception.log',
    'GAUGE_LOG': _PREFIX + '/var/log/ryu/faucet/gauge.log',
}


def get_setting(name):
    """Returns value of specified configuration setting."""
    return os.getenv(name, DEFAULTS[name])


def get_logger(logname, logfile, loglevel, propagate):
    """Create and return a logger object."""
    logger = logging.getLogger(logname)
    logger_handler = WatchedFileHandler(logfile)
    log_fmt = '%(asctime)s %(name)-6s %(levelname)-8s %(message)s'
    logger_handler.setFormatter(
        logging.Formatter(log_fmt, '%b %d %H:%M:%S'))
    logger.addHandler(logger_handler)
    logger.propagate = propagate
    logger.setLevel(loglevel)
    return logger


def dpid_log(dpid):
    """Log a DP ID as hex/decimal."""
    return 'DPID %u (0x%x)' % (dpid, dpid)


def btos(b_str):
    """Return byte array/string as string."""
    return b_str.encode('utf-8').decode('utf-8', 'strict')
