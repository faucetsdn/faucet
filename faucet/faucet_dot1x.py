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


class FaucetDot1x:
    """Wrapper for experimental Chewie 802.1x authenticator."""

    def __init__(self, logger, metrics, send_flow_msgs):
        self.logger = logger
        self.metrics = metrics
        self._send_flow_msgs = send_flow_msgs
        self._valves = None
        self.dot1x_speaker = None
        self.dot1x_intf = None
        self.mac_to_port = {}  # {"00:00:00:00:00:02" : (valve_0, port_1)}

    def _create_dot1x_speaker(self, dot1x_intf):
        chewie = Chewie(  # pylint: disable=too-many-function-args
            dot1x_intf, self.logger,
            self.auth_handler, self.failure_handler, self.logoff_handler,
            '127.0.0.1')
        hub.spawn(chewie.run)
        return chewie

    def get_valve_and_port(self, port_id):
        """Finds the valve and port that this address corresponds to
        Args:
            port_id: is a macaddress string"""
        valve, port = self.mac_to_port[port_id]
        return valve, port

    def auth_handler(self, address, port_id):
        """Callback for when a successful auth happens."""
        valve, dot1x_port = self.get_valve_and_port(port_id)

        self.logger.info(
            'Successful auth from MAC %s on %s' % (
                str(address), dot1x_port))
        self.metrics.inc_var('dp_dot1x_success', valve.base_prom_labels)
        self.metrics.inc_var('port_dot1x_success', valve.port_labels(dot1x_port))

        flowmods = valve.add_authed_mac(
            dot1x_port.number, str(address))
        if flowmods:
            self._send_flow_msgs(valve, flowmods)

    def logoff_handler(self, address, port_id):
        """Callback for when an EAP logoff happens."""
        valve, dot1x_port = self.get_valve_and_port(port_id)
        self.logger.info('Logoff from MAC %s on %s',
                         str(address), dot1x_port)
        self.metrics.inc_var('dp_dot1x_logoff', valve.base_prom_labels)
        self.metrics.inc_var('port_dot1x_logoff', valve.port_labels(dot1x_port))
        flowmods = valve.del_authed_mac(dot1x_port.number, str(address))
        if flowmods:
            self._send_flow_msgs(valve, flowmods)

    def failure_handler(self, address, port_id):
        """Callback for when a EAP failure happens."""
        valve, dot1x_port = self.get_valve_and_port(port_id)
        self.logger.info('Failure from MAC %s on %s',
                         str(address), dot1x_port)
        self.metrics.inc_var('dp_dot1x_failure', valve.base_prom_labels)
        self.metrics.inc_var('port_dot1x_failure', valve.port_labels(dot1x_port))

    def reset(self, valves):
        """Set up a dot1x speaker."""
        # TODO: support multiple Valves and ports.
        self._valves = valves
        valve_id = -1
        for valve in list(valves.values()):
            valve_id += 1
            if self.dot1x_speaker is None:
                if valve.dp.dot1x:
                    dot1x_intf = valve.dp.dot1x['nfv_intf']
                    self.dot1x_speaker = self._create_dot1x_speaker(dot1x_intf)
                else:
                    continue
            if valve.dp.dot1x and valve.dp.dot1x_ports():
                for dot1x_port in valve.dp.dot1x_ports():
                    if dot1x_port.number > 255:
                        self.logger.info('dot1x not enabled on %s %s. Port number is larger than 255'
                                         % (valve.dp, dot1x_port))
                        continue
                    if valve_id > 255:
                        self.logger.info('dot1x not enabled on %s %s. more than 255 valves'
                                         % (valve.dp, dot1x_port))
                        continue
                    mac_str = "00:00:00:00:%02x:%02x" % (valve_id, dot1x_port.number)
                    self.mac_to_port[mac_str] = (valve, dot1x_port)
                    self.logger.info(
                        'dot1x enabled on %s (%s) port %s, NFV interface %s' % (
                            valve.dp, valve_id, dot1x_port, dot1x_intf))
