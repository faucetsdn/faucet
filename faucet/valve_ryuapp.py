"""RyuApp base class for FAUCET/Gauge."""

# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
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
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
import random
import signal
import sys

from ryu.base import app_manager
from ryu.controller import event
from ryu.lib import hub

from faucet import valve_of
from faucet.valve_util import get_logger, get_setting


class EventReconfigure(event.EventBase):
    """Event sent to controller to cause config reload."""

    pass


class RyuAppBase(app_manager.RyuApp):
    """RyuApp base class for FAUCET/Gauge."""

    OFP_VERSIONS = valve_of.OFP_VERSIONS
    logname = ''
    exc_logname = ''

    def __init__(self, *args, **kwargs):
        super(RyuAppBase, self).__init__(*args, **kwargs)
        self.dpset = kwargs['dpset']
        self.config_file = self.get_setting('CONFIG', True)
        self.stat_reload = self.get_setting('CONFIG_STAT_RELOAD')
        loglevel = self.get_setting('LOG_LEVEL')
        logfile = self.get_setting('LOG')
        exc_logfile = self.get_setting('EXCEPTION_LOG')
        self.logger = get_logger(
            self.logname, logfile, loglevel, 0)
        self.exc_logger = get_logger(
            self.exc_logname, exc_logfile, logging.DEBUG, 1)

    @staticmethod
    def _thread_jitter(period, jitter=3):
        """Reschedule another thread with a random jitter."""
        hub.sleep(period + random.randint(0, jitter))

    def get_setting(self, setting, path_eval=False):
        """Return config setting prefaced with logname."""
        return get_setting('_'.join((self.logname.upper(), setting)), path_eval)

    def signal_handler(self, sigid, _):
        """Handle signals.

        Args:
            sigid (int): signal received.
        """
        if sigid == signal.SIGINT:
            self.close()
            sys.exit(0)
        if sigid == signal.SIGHUP:
            self.send_event(self.__class__.__name__, EventReconfigure())

    def start(self):
        """Start controller."""
        super(RyuAppBase, self).start()

        self.logger.info('Loaded configuration from %s', self.config_file)

        if self.stat_reload:
            self.logger.info('will automatically reload new config on changes')
        signal.signal(signal.SIGHUP, self.signal_handler)
        signal.signal(signal.SIGINT, self.signal_handler)
