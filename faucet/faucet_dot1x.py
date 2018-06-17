"""802.1x implementation for FAUCET."""

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
# distributed under the License is distributed on an "AS IS" BASIS
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import eventlet
eventlet.monkey_patch()

from ryu.lib import hub # pylint: disable=wrong-import-position

from chewie.chewie import Chewie # pylint: disable=wrong-import-position
from chewie.mac_address import MacAddress # pylint: disable=wrong-import-position


class FaucetDot1x(object):
    """Wrapper for Ryu BGP speaker."""

    INTERFACE = 'lo'
    PORT_NUM = 1
    CREDENTIALS = {
        'gary': 'microphone',
    }

    def __init__(self, logger, metrics, send_flow_msgs):
        self.logger = logger
        self.metrics = metrics
        self._send_flow_msgs = send_flow_msgs
        self.dot1x_speaker = None
        self._valve = None

    def _create_dot1x_speaker(self):
        chewie = Chewie(
            self.INTERFACE, self.CREDENTIALS,
            self.logger, self.auth_handler,
            MacAddress.from_string('00:00:00:00:00:01'))
        hub.spawn(chewie.run)
        return chewie

    def auth_handler(self, address, _group_address):
        """Callback for when a successful auth happens."""

        self.logger.info(
            'Successful auth from MAC %s on port %u' % (str(address), self.PORT_NUM))
        flowmods = self._valve.add_authed_mac(self.PORT_NUM, str(address))
        if flowmods:
            self._send_flow_msgs(self._valve, flowmods)

    def reset(self, valves):
        """Set up a dot1x speaker."""
        if len(valves) > 1:
            self.logger.warning('Dot1x only supports 1 Valve.')
        if valves:
            self._valve = list(valves.values())[0]
            if self._valve.dp.dot1x_ports():
                self.dot1x_speaker = self._create_dot1x_speaker()
