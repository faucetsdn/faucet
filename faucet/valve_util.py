"""Utility functions for FAUCET."""

# Copyright (C) 2015 Brad Cowie, Christopher Lorier and Joe Stringer.
# Copyright (C) 2015 Research and Education Advanced Network New Zealand Ltd.
# Copyright (C) 2015--2018 The Contributors
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


def utf8_decode(msg_str):
    """Gracefully decode a possibly UTF-8 string."""
    return msg_str.decode('utf-8', errors='replace')


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
# To specify a boolean-only setting, set the default value to a bool type.
DEFAULTS = {
    'FAUCET_CONFIG': ''.join((
        _PREFIX,
        '/etc/faucet/faucet.yaml',
        ':',
        _PREFIX,
        '/etc/ryu/faucet/faucet.yaml')),
    'FAUCET_CONFIG_STAT_RELOAD': False,
    'FAUCET_LOG_LEVEL': 'INFO',
    'FAUCET_LOG': _PREFIX + '/var/log/faucet/faucet.log',
    'FAUCET_EVENT_SOCK': '',  # Special-case, see get_setting().
    'FAUCET_EXCEPTION_LOG': _PREFIX + '/var/log/faucet/faucet_exception.log',
    'FAUCET_PROMETHEUS_PORT': '9302',
    'FAUCET_PROMETHEUS_ADDR': '0.0.0.0',
    'FAUCET_PIPELINE_DIR': _PREFIX + '/etc/faucet' + ':' + _PREFIX + '/etc/ryu/faucet',
    'GAUGE_CONFIG': ''.join((
        _PREFIX,
        '/etc/faucet/gauge.yaml',
        ':',
        _PREFIX,
        '/etc/ryu/faucet/gauge.yaml')),
    'GAUGE_CONFIG_STAT_RELOAD': False,
    'GAUGE_LOG_LEVEL': 'INFO',
    'GAUGE_PROMETHEUS_ADDR': '0.0.0.0',
    'GAUGE_EXCEPTION_LOG': _PREFIX + '/var/log/faucet/gauge_exception.log',
    'GAUGE_LOG': _PREFIX + '/var/log/faucet/gauge.log'
}


def _cast_bool(value):
    """Return True if value is a non-zero int."""
    try:
        return int(value) != 0
    except ValueError:
        return False


def get_setting(name, path_eval=False):
    """Returns value of specified configuration setting."""
    default_value = DEFAULTS[name]
    result = os.getenv(name, default_value)
    # split on ':' and find the first suitable path
    if (path_eval and
            isinstance(result, str) and
            isinstance(default_value, str) and not
            isinstance(default_value, bool)):
        locations = result.split(":")
        result = None
        for loc in locations:
            if os.path.isfile(loc):
                result = loc
                break
        if result is None:
            result = locations[0]
    # Check for setting that expects a boolean result.
    if isinstance(default_value, bool):
        return _cast_bool(result)
    # Special default for FAUCET_EVENT_SOCK.
    if name == 'FAUCET_EVENT_SOCK':
        if result == '0':
            return ''
        if _cast_bool(result):
            return _PREFIX + '/var/run/faucet/faucet.sock'
    return result


def get_logger(logname, logfile, loglevel, propagate):
    """Create and return a logger object."""

    stream_handlers = {
        'STDOUT': sys.stdout,
        'STDERR': sys.stderr,
    }

    try:
        if logfile in stream_handlers:
            logger_handler = logging.StreamHandler(stream_handlers[logfile])
        else:
            logger_handler = WatchedFileHandler(logfile)
    except (PermissionError, FileNotFoundError) as err: # pytype: disable=name-error
        print(err)
        sys.exit(-1)

    logger = logging.getLogger(logname)
    log_fmt = '%(asctime)s %(name)-6s %(levelname)-8s %(message)s'
    logger_handler.setFormatter(
        logging.Formatter(log_fmt, '%b %d %H:%M:%S'))
    logger.addHandler(logger_handler)
    logger.propagate = propagate
    logger.setLevel(loglevel)
    return logger


def close_logger(logger):
    """Close all handlers on logger object."""
    if logger is None:
        return
    for handler in list(logger.handlers):
        handler.close()
        logger.removeHandler(handler)


def dpid_log(dpid):
    """Log a DP ID as hex/decimal."""
    return 'DPID %u (0x%x)' % (dpid, dpid)


def btos(b_str):
    """Return byte array/string as string."""
    return b_str.encode('utf-8').decode('utf-8', 'strict')


def stat_config_files(config_hashes):
    """Return dict of a subset of stat attributes on config files."""
    config_files_stats = {}
    for config_file in list(config_hashes.keys()):
        try:
            config_file_stat = os.stat(config_file)
        except OSError:
            continue
        config_files_stats[config_file] = (
            config_file_stat.st_size,
            config_file_stat.st_mtime,
            config_file_stat.st_ctime)
    return config_files_stats
