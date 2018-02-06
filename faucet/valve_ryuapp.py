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

from ryu.base import app_manager
from ryu.controller import dpset
from ryu.lib import hub
from faucet import valve_of
from faucet.valve_util import get_logger, get_setting


class RyuAppBase(app_manager.RyuApp):
    """RyuApp base class for FAUCET/Gauge."""

    _CONTEXTS = {'dpset': dpset.DPSet}
    OFP_VERSIONS = valve_of.OFP_VERSIONS
    logname = ''
    exc_logname = ''

    def __init__(self, *args, **kwargs):
        super(RyuAppBase, self).__init__(*args, **kwargs)
        self.dpset = kwargs['dpset']
        self.logger, self.exc_logger = self.setup_logging()
        self.config_file = self.get_setting('CONFIG')

    def get_setting(self, setting):
        return get_setting('_'.join((self.logname.upper(), setting)))

    def setup_logging(self):
        logger = get_logger(
            self.logname, self.get_setting('LOG'), self.get_setting('LOG_LEVEL'), 0)
        exc_logger = get_logger(
            self.exc_logname, self.get_setting('EXCEPTION_LOG'), logging.DEBUG, 1)
        return (logger, exc_logger)

    @staticmethod
    def _thread_jitter(period, jitter=2):
        """Reschedule another thread with a random jitter."""
        hub.sleep(period + random.randint(0, jitter))

    def _thread_reschedule(self, ryu_event, period, jitter=2):
        """Trigger Ryu events periodically with a jitter.

        Args:
            ryu_event (ryu.controller.event.EventReplyBase): event to trigger.
            period (int): how often to trigger.
        """
        while True:
            self.send_event(self.logname, ryu_event)
            self._thread_jitter(period, jitter)
