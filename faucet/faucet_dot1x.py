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
from chewie import chewie  # pylint: disable=wrong-import-position

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
        """

        Args:
            dot1x_intf (str):
            chewie_id (str):
            radius_ip (str):
            radius_port (int):
            radius_secret (str):

        Returns:
            Chewie
        """
        _chewie = chewie.Chewie(  # pylint: disable=too-many-function-args
            dot1x_intf, self.logger,
            self.auth_handler, self.failure_handler, self.logoff_handler,
            radius_ip, radius_port, radius_secret, chewie_id)
        hub.spawn(_chewie.run)
        return _chewie

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
        self.metrics.inc_var('dp_dot1x_success', valve.dp.base_prom_labels())
        self.metrics.inc_var('port_dot1x_success', valve.dp.port_labels(dot1x_port.number))

        flowmods = valve.add_authed_mac(
            dot1x_port.number, str(address))
        if flowmods:
            self._send_flow_msgs(valve, flowmods)

    def logoff_handler(self, address, port_id):
        """Callback for when an EAP logoff happens."""
        valve, dot1x_port = self.get_valve_and_port(port_id)
        self.logger.info(
            'Logoff from MAC %s on %s', str(address), dot1x_port)
        self.metrics.inc_var('dp_dot1x_logoff', valve.dp.base_prom_labels())
        self.metrics.inc_var('port_dot1x_logoff', valve.dp.port_labels(dot1x_port.number))
        flowmods = valve.del_authed_mac(
            dot1x_port.number, str(address))
        if flowmods:
            self._send_flow_msgs(valve, flowmods)

    def failure_handler(self, address, port_id):
        """Callback for when a EAP failure happens."""
        valve, dot1x_port = self.get_valve_and_port(port_id)
        self.logger.info(
            'Failure from MAC %s on %s', str(address), dot1x_port)
        self.metrics.inc_var('dp_dot1x_failure', valve.dp.base_prom_labels())
        self.metrics.inc_var('port_dot1x_failure', valve.dp.port_labels(dot1x_port.number))

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
        nfv_sw_port = valve.dp.dot1x['nfv_sw_port']

        if dot1x_port.number == nfv_sw_port:
            ret = []
            for port in valve.dp.dot1x_ports():
                ret.extend(
                    self.create_flow_pair(port, nfv_sw_port, valve))
            return ret

        return self.create_flow_pair(dot1x_port, nfv_sw_port, valve)

    def create_flow_pair(self, dot1x_port, nfv_sw_port, valve):
        """Creates the pair of flows that redirects the eapol packets to/from the supplicant and
        nfv port

        Args:
            dot1x_port (Port):
            nfv_sw_port (int):
            valve (Valve):

        Returns:
            list
        """
        port_acl_table = valve.dp.tables['port_acl']
        valve_index = self.dp_id_to_valve_index[valve.dp.dp_id]
        mac = get_mac_str(valve_index, dot1x_port.number)

        if dot1x_port.running():
            return [
                port_acl_table.flowmod(
                    inst=[valve_of.apply_actions([
                        valve_of.set_field(eth_dst=mac),
                        valve_of.output_port(nfv_sw_port)])],
                    **FaucetDot1x.get_dot1x_port_match_priority(dot1x_port, port_acl_table, valve)),
                port_acl_table.flowmod(
                    inst=[valve_of.apply_actions([
                        valve_of.set_field(eth_src=EAPOL_DST),
                        valve_of.output_port(dot1x_port.number)])],
                    **FaucetDot1x.get_nfv_sw_port_match_priority(mac, nfv_sw_port,
                                                                 port_acl_table, valve)
                )]
        return []

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
        # Strictly speaking these deletes aren't needed, as the caller
        # clears the port_acl table for # the port that is down.
        return [
            port_acl_table.flowdel(
                **FaucetDot1x.get_dot1x_port_match_priority(dot1x_port, port_acl_table, valve)),
            port_acl_table.flowdel(
                **FaucetDot1x.get_nfv_sw_port_match_priority(mac, nfv_sw_port,
                                                             port_acl_table, valve)
                )]

    @staticmethod
    def get_nfv_sw_port_match_priority(mac, nfv_sw_port, port_acl_table, valve):
        """Create the match for eapol coming from the nfv_sw_port.
        Args:
            mac (str): the MacAddress of the dot1x (supplicant port)
            nfv_sw_port (int):
            port_acl_table (ValveTable):
            valve (Valve):

        Returns:
            dict containing a match and priority.
        """
        return {'match': port_acl_table.match(
            in_port=nfv_sw_port,
            eth_type=valve_packet.ETH_EAPOL,
            eth_src=mac),
                'priority': valve.dp.highest_priority}

    @staticmethod
    def get_dot1x_port_match_priority(dot1x_port, port_acl_table, valve):
        """Create the match for eapol coming from the supplicant's port.
        Args:
            dot1x_port (Port): supplicant port.
            port_acl_table (ValveTable):
            valve (Valve):

        Returns:
            dict containing a match and priority.
        """
        return {'match': port_acl_table.match(
            in_port=dot1x_port.number,
            eth_type=valve_packet.ETH_EAPOL),
                'priority': valve.dp.highest_priority}

    def reset(self, valves):
        """Set up a dot1x speaker."""
        self._valves = valves
        dot1x_valves = [
            valve for valve in valves.values() if valve.dp.dot1x and valve.dp.dot1x_ports()]
        assert len(dot1x_valves) < 255, 'dot1x not supported for > 255 DPs'
        if not dot1x_valves:
            return

        first_valve = dot1x_valves[0]
        dot1x_intf = first_valve.dp.dot1x['nfv_intf']
        radius_ip = first_valve.dp.dot1x['radius_ip']
        radius_port = first_valve.dp.dot1x['radius_port']
        radius_secret = first_valve.dp.dot1x['radius_secret']
        self.dot1x_speaker = self._create_dot1x_speaker(
            dot1x_intf, first_valve.dp.faucet_dp_mac,
            radius_ip, radius_port, radius_secret)

        for valve_index, valve in enumerate(dot1x_valves, start=0):
            self.dp_id_to_valve_index[valve.dp.dp_id] = valve_index
            for dot1x_port in valve.dp.dot1x_ports():
                self.set_mac_str(valve, valve_index, dot1x_port.number)
                self.logger.info(
                    'dot1x enabled on %s (%s) port %s, NFV interface %s' % (
                        valve.dp, valve_index, dot1x_port, dot1x_intf))
