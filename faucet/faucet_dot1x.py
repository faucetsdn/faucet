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

from ryu.lib import hub  # pylint: disable=wrong-import-position
from chewie.chewie import Chewie  # pylint: disable=wrong-import-position

from faucet import valve_of # pylint: disable=wrong-import-position
from faucet import valve_packet # pylint: disable=wrong-import-position


EAPOL_DST = '01:80:c2:00:00:03'


def get_mac_str(valve_index, port_num):
    """Gets the mac address string for the valve/port combo
    Args:
        valve_index (int): The internally used id of the valve.
        port_num (int): port number

    Returns:
        str
    """
    return '00:00:00:00:%02x:%02x' % (valve_index, port_num)


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
        self.dp_id_to_valve_index = {}

    def _create_dot1x_speaker(self, dot1x_intf, chewie_id, radius_ip, radius_port, radius_secret):
        chewie = Chewie(  # pylint: disable=too-many-function-args
            dot1x_intf, self.logger,
            self.auth_handler, self.failure_handler, self.logoff_handler,
            radius_ip, radius_port, radius_secret, chewie_id)
        hub.spawn(chewie.run)
        return chewie

    def get_valve_and_port(self, port_id):
        """Finds the valve and port that this address corresponds to
        Args:
            port_id: is a macaddress string"""
        valve, port = self.mac_to_port[port_id]
        return (valve, port)

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
        self.logger.info(
            'Logoff from MAC %s on %s', str(address), dot1x_port)
        self.metrics.inc_var('dp_dot1x_logoff', valve.base_prom_labels)
        self.metrics.inc_var('port_dot1x_logoff', valve.port_labels(dot1x_port))
        flowmods = valve.del_authed_mac(
            dot1x_port.number, str(address))
        if flowmods:
            self._send_flow_msgs(valve, flowmods)

    def failure_handler(self, address, port_id):
        """Callback for when a EAP failure happens."""
        valve, dot1x_port = self.get_valve_and_port(port_id)
        self.logger.info(
            'Failure from MAC %s on %s', str(address), dot1x_port)
        self.metrics.inc_var('dp_dot1x_failure', valve.base_prom_labels)
        self.metrics.inc_var('port_dot1x_failure', valve.port_labels(dot1x_port))

    def set_mac_str(self, valve, valve_index, port_num):
        """
        Args:
            valve (Valve):
            valve_index (int):
            port_num (int):

        Returns:
            str
        """
        mac_str = get_mac_str(valve_index, port_num)
        port = valve.dp.ports[port_num]
        self.mac_to_port[mac_str] = (valve, port)
        return mac_str

    def get_port_acls(self, valve, dot1x_port):
        """Setup the dot1x forward port acls.
        Args:
            dot1x_port:
            valve:

        Returns:
            list of flowmods
        """
        port_acl_table = valve.dp.tables['port_acl']
        nfv_sw_port = valve.dp.dot1x['nfv_sw_port']
        valve_index = self.dp_id_to_valve_index[valve.dp.dp_id]
        mac = get_mac_str(valve_index, dot1x_port.number)
        ofmsgs = []
        ofmsgs.append(port_acl_table.flowmod(
            port_acl_table.match(
                in_port=dot1x_port.number,
                eth_type=valve_packet.ETH_EAPOL),
            priority=valve.dp.highest_priority,
            inst=[valve_of.apply_actions([
                valve_of.set_field(eth_dst=mac),
                valve_of.output_port(nfv_sw_port)])]))
        ofmsgs.append(port_acl_table.flowmod(
            port_acl_table.match(
                in_port=nfv_sw_port,
                eth_type=valve_packet.ETH_EAPOL,
                eth_src=mac),
            priority=valve.dp.highest_priority,
            inst=[valve_of.apply_actions([
                valve_of.set_field(eth_src=EAPOL_DST),
                valve_of.output_port(dot1x_port.number)])]))
        return ofmsgs

    def port_down(self, valve, dot1x_port):
        """
        Remove the acls added by FaucetDot1x.get_port_acls
        Args:
            valve:
            dot1x_port:

        Returns:
            list of flowmods
        """
        # TODO: let chewie know about the port down event.
        port_acl_table = valve.dp.tables['port_acl']
        nfv_sw_port = valve.dp.dot1x['nfv_sw_port']
        valve_index = self.dp_id_to_valve_index[valve.dp.dp_id]
        mac = get_mac_str(valve_index, dot1x_port.number)
        ofmsgs = []
        # Strictly speaking these deletes aren't needed, as the caller
        # clears the port_acl table for # the port that is down.
        ofmsgs.extend(port_acl_table.flowdel(
            match=port_acl_table.match(
                in_port=dot1x_port.number,
                eth_type=valve_packet.ETH_EAPOL),
            priority=valve.dp.highest_priority))
        ofmsgs.extend(port_acl_table.flowdel(
            match=port_acl_table.match(
                in_port=nfv_sw_port,
                eth_type=valve_packet.ETH_EAPOL,
                eth_src=mac),
            priority=valve.dp.highest_priority))
        return ofmsgs

    def reset(self, valves):
        """Set up a dot1x speaker."""
        self._valves = valves
        self.dot1x_speaker = None
        dot1x_intf = None

        for valve_index, valve in enumerate(list(valves.values()), start=0):
            self.dp_id_to_valve_index[valve.dp.dp_id] = valve_index
            if self.dot1x_speaker is None:
                if not valve.dp.dot1x:
                    continue
                dot1x_intf = valve.dp.dot1x['nfv_intf']
                radius_ip = valve.dp.dot1x['radius_ip']
                radius_port = valve.dp.dot1x['radius_port']
                radius_secret = valve.dp.dot1x['radius_secret']
                self.dot1x_speaker = self._create_dot1x_speaker(
                    dot1x_intf, valve.dp.faucet_dp_mac,
                    radius_ip, radius_port, radius_secret)
            if valve.dp.dot1x and valve.dp.dot1x_ports():
                if valve_index > 255:
                    self.logger.info(
                        'dot1x not enabled on %s: more than 255 valves' % valve.dp)
                    continue
                for dot1x_port in valve.dp.dot1x_ports():
                    self.set_mac_str(valve, valve_index, dot1x_port.number)
                    self.logger.info(
                        'dot1x enabled on %s (%s) port %s, NFV interface %s' % (
                            valve.dp, valve_index, dot1x_port, dot1x_intf))
