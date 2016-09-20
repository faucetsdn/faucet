# Copyright (C) 2015 Brad Cowie, Christopher Lorier and Joe Stringer.
# Copyright (C) 2015 Research and Education Advanced Network New Zealand Ltd.
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
import os
import signal
import sys
from functools import wraps


def dump(obj, level=0):
    prefix = level*'*'+' ' if level > 0 else ''

    if isinstance(obj, dict):
        for k, v in obj.items():
            if hasattr(v, '__iter__'):
                print "%s%s" % (prefix, k)
                dump(v, level+1)
            else:
                print "%s%s : %s" % (prefix, k, v)
    elif isinstance(obj, list):
        for v in obj:
            if hasattr(v, '__iter__'):
                dump(v, level+1)
            else:
                print "%s%s" % (prefix, v)
    else:
        print "%s%s" % (prefix, obj)


def mac_addr_is_unicast(mac_addr):
    """Returns True if mac_addr is a unicast ethernet address.

    arguments:
    mac_addr - a string representation of a mac address."""
    msb = mac_addr.split(":")[0]
    return msb[-1] in "02468aAcCeE"

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
                    "Unhandled exception, killing RYU")
                logging.shutdown()
                os.kill(os.getpid(), signal.SIGKILL)
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
    sysprefix = ""
    if (getattr(sys, "real_prefix", sys.prefix) != sys.prefix or
        getattr(sys, "base_prefix", sys.prefix) != sys.prefix):
        sysprefix = sys.prefix

    return sysprefix
