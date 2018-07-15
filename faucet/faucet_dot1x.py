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


class FaucetDot1x:
    """Wrapper for experimental Chewie 802.1x authenticator."""

    # TODO: support other credentials.
    CREDENTIALS = {
        'gary': 'microphone',
    }

    def __init__(self, logger, metrics, send_flow_msgs):
        self.logger = logger
        self.metrics = metrics
        self._send_flow_msgs = send_flow_msgs
        self._valve = None
        self.dot1x_speaker = None
        self.dot1x_intf = None
        self.dot1x_port = None

    def _create_dot1x_speaker(self):
        chewie = Chewie(
            self.dot1x_intf, self.CREDENTIALS,
            self.logger, self.auth_handler,
            MacAddress.from_string('00:00:00:00:00:01'))
        hub.spawn(chewie.run)
        return chewie

    def auth_handler(self, address, _group_address):
        """Callback for when a successful auth happens."""
        self.logger.info(
            'Successful auth from MAC %s on %s' % (
                str(address), self.dot1x_port))
        flowmods = self._valve.add_authed_mac(
            self.dot1x_port.number, str(address))
        if flowmods:
            self._send_flow_msgs(self._valve, flowmods)

    def reset(self, valves):
        """Set up a dot1x speaker."""
        # TODO: support multiple Valves and ports.
        if self.dot1x_speaker is None:
            for valve in list(valves.values()):
                if valve.dp.dot1x and valve.dp.dot1x_ports():
                    self._valve = valve
                    self.dot1x_intf = self._valve.dp.dot1x['nfv_intf']
                    self.dot1x_port = self._valve.dp.dot1x_ports()[0]
                    self.dot1x_speaker = self._create_dot1x_speaker()
                    self.logger.info(
                        'dot1x enabled on %s %s, NFV interface %s' % (
                            self._valve.dp, self.dot1x_port, self.dot1x_intf))
                    break
