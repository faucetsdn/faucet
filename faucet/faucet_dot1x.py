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


def get_mac_str(valve_index, port_num):
    """Gets the mac address string for the valve/port combo
    Args:
        valve_index (int): The internally used id of the valve.
        port_num (int): port number

    Returns:
        str
    """
    two_byte_port_num = ("%04x" % port_num)
    two_byte_port_num_formatted = two_byte_port_num[:2] + ':' + two_byte_port_num[2:]
    return '00:00:00:%02x:%s' % (valve_index, two_byte_port_num_formatted)


class FaucetDot1x:
    """Wrapper for experimental Chewie 802.1x authenticator."""

    def __init__(self, logger, metrics, send_flow_msgs):
        self.logger = logger
        self.metrics = metrics
        self.mac_to_port = {}  # {"00:00:00:00:00:02" : (valve_0, port_1)}
        self.dp_id_to_valve_index = {}
        self.thread = None

        self._send_flow_msgs = send_flow_msgs
        self._valves = None
        self._dot1x_speaker = None
        self._auth_acl_name = None
        self._noauth_acl_name = None

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
        self.thread = hub.spawn(_chewie.run)
        self.thread.name = 'chewie'
        return _chewie

    def _get_valve_and_port(self, port_id):
        """Finds the valve and port that this address corresponds to
        Args:
            port_id: is a macaddress string"""
        valve, port = self.mac_to_port[port_id]
        return (valve, port)

    def _get_acls(self, dp):
        """Returns tuple of acl values"""
        auth_acl = dp.acls.get(self._auth_acl_name)
        noauth_acl = dp.acls.get(self._noauth_acl_name)
        return (auth_acl, noauth_acl)

    # Loggin Methods
    def log_auth_event(self, valve, port_num, mac_str, status):
        """Log an authentication attempt event"""
        self.metrics.inc_var('dp_dot1x_{}'.format(status), valve.dp.base_prom_labels())
        self.metrics.inc_var('port_dot1x_{}'.format(status), valve.dp.port_labels(port_num))
        self.logger.info(
            '{} from MAC {} on {}'.format(status.capitalize(), mac_str, port_num))
        valve.dot1x_event({'AUTHENTICATION': {'dp_id': valve.dp.dp_id,
                                              'port': port_num,
                                              'eth_src': mac_str,
                                              'status': status}})

    def log_port_event(self, event_type, port_type, valve, port_num):
        """Log a dot1x port event"""
        valve.dot1x_event({event_type: {'dp_id': valve.dp.dp_id,
                                        'port': port_num,
                                        'port_type': port_type}})

    def auth_handler(self, address, port_id, vlan_name, filter_id):
        """Callback for when a successful auth happens."""
        address_str = str(address)
        valve, dot1x_port = self._get_valve_and_port(port_id)
        port_num = dot1x_port.number

        self.log_auth_event(valve, port_num, address_str, 'success')
        flowmods = self._get_login_flowmod(dot1x_port, valve, address_str, vlan_name)

        if flowmods:
            self._send_flow_msgs(valve, flowmods)

    def logoff_handler(self, address, port_id):
        """Callback for when an EAP logoff happens."""
        address_str = str(address)
        valve, dot1x_port = self._get_valve_and_port(port_id)
        port_num = dot1x_port.number

        self.log_auth_event(valve, port_num, address_str, 'logoff')

        flowmods = self._get_logoff_flowmod(dot1x_port, valve, address_str)

        if flowmods:
            self._send_flow_msgs(valve, flowmods)

    def failure_handler(self, address, port_id):
        """Callback for when a EAP failure happens."""
        address_str = str(address)

        valve, dot1x_port = self._get_valve_and_port(port_id)
        port_num = dot1x_port.number

        self.log_auth_event(valve, port_num, address_str, 'failure')
        flowmods = self._get_logoff_flowmod(dot1x_port, valve, address_str)

        if flowmods:
            self._send_flow_msgs(valve, flowmods)

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

    def nfv_sw_port_up(self, dp_id, dot1x_ports, nfv_sw_port):
        """Setup the dot1x forward port acls when the nfv_sw_port comes up.
        Args:
            dp_id (int):
            dot1x_ports (Iterable of Port objects):
            nfv_sw_port (Port):

        Returns:
            list of flowmods
        """
        #TODO Come back to. Should this be down?
        self._dot1x_speaker.port_down(
            get_mac_str(self.dp_id_to_valve_index[dp_id], nfv_sw_port.number))
        valve = self._valves[dp_id]

        self.log_port_event("PORT_UP", 'nfv', valve, nfv_sw_port.number)

        ret = []
        for port in dot1x_ports:
            ret.extend(self.create_flow_pair(
                dp_id, port, nfv_sw_port, valve))
        return ret

    def port_up(self, dp_id, dot1x_port, nfv_sw_port):
        """Setup the dot1x forward port acls.
        Args:
            dp_id (int):
            dot1x_port (Port):
            nfv_sw_port (Port):

        Returns:
            list of flowmods
        """
        port_num = dot1x_port.number

        mac_str = get_mac_str(self.dp_id_to_valve_index[dp_id], port_num)
        self._dot1x_speaker.port_up(mac_str)
        valve = self._valves[dp_id]

        self.log_port_event("PORT_UP", 'supplicant', valve, port_num)

        # Dealing with ACLs
        flowmods = []
        flowmods.extend(self.create_flow_pair(
            dp_id, dot1x_port, nfv_sw_port, valve))

        flowmods.extend(self._add_unauthenticated_flowmod(dot1x_port, valve))

        return flowmods

    def create_flow_pair(self, dp_id, dot1x_port, nfv_sw_port, valve):
        """Creates the pair of flows that redirects the eapol packets to/from
        the supplicant and nfv port

        Args:
            dp_id (int):
            dot1x_port (Port):
            nfv_sw_port (Port):
            valve (Valve):

        Returns:
            list
        """
        if dot1x_port.running():
            valve_index = self.dp_id_to_valve_index[dp_id]
            mac = get_mac_str(valve_index, dot1x_port.number)
            return valve.create_dot1x_flow_pair(
                dot1x_port.number, nfv_sw_port.number, mac)
        return []

    def port_down(self, dp_id, dot1x_port, nfv_sw_port):
        """
        Remove the acls added by FaucetDot1x.get_port_acls
        Args:
            dp_id (int):
            dot1x_port (Port):
            nfv_sw_port (Port):

        Returns:
            list of flowmods
        """
        valve_index = self.dp_id_to_valve_index[dp_id]
        port_num = dot1x_port.number

        mac = get_mac_str(valve_index, port_num)
        self._dot1x_speaker.port_down(mac)

        valve = self._valves[dp_id]
        self.log_port_event("PORT_DOWN", 'supplicant', valve, port_num)

        flowmods = []
        flowmods.extend(self._del_authenticated_flowmod(dot1x_port, valve, mac))
        flowmods.extend(self._del_unauthenticated_flowmod(dot1x_port, valve))
        # NOTE: The flow_pair are not included in unauthed flowmod
        flowmods.extend(valve.del_dot1x_flow_pair(dot1x_port.number, nfv_sw_port.number, mac))
        return flowmods

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

        self._auth_acl_name = first_valve.dp.dot1x.get('auth_acl')
        self._noauth_acl_name = first_valve.dp.dot1x.get('noauth_acl')

        self._dot1x_speaker = self._create_dot1x_speaker(
            dot1x_intf, first_valve.dp.faucet_dp_mac,
            radius_ip, radius_port, radius_secret)

        for valve_index, valve in enumerate(dot1x_valves, start=0):
            self.dp_id_to_valve_index[valve.dp.dp_id] = valve_index
            for dot1x_port in valve.dp.dot1x_ports():
                self.set_mac_str(valve, valve_index, dot1x_port.number)
                self.logger.info(
                    'dot1x enabled on %s (%s) port %s, NFV interface %s' % (
                        valve.dp, valve_index, dot1x_port, dot1x_intf))

            valve.dot1x_event({'ENABLED': {'dp_id': valve.dp.dp_id}})

    def _get_logoff_flowmod(self, dot1x_port, valve, mac_str):
        """Return flowmods required to logoff port"""
        flowmods = []
        flowmods.extend(
            self._del_authenticated_flowmod(dot1x_port, valve, mac_str))
        flowmods.extend(
            self._add_unauthenticated_flowmod(dot1x_port, valve))
        return flowmods

    def _get_login_flowmod(self, dot1x_port, valve, mac_str, vlan_name):
        """Return flowmods required to login port"""
        flowmods = []
        flowmods.extend(
            self._del_unauthenticated_flowmod(dot1x_port, valve))
        flowmods.extend(
            self._add_authenticated_flowmod(dot1x_port, valve, mac_str, vlan_name))

        return flowmods

    def _add_authenticated_flowmod(self, dot1x_port, valve, mac_str, vlan_name):
        """Return flowmods for successful authentication on port"""
        port_num = dot1x_port.number
        flowmods = []

        if dot1x_port.dot1x_acl:
            auth_acl, _ = self._get_acls(valve.dp)
            flowmods.extend(valve.add_port_acl(auth_acl, port_num, mac_str))
        else:
            flowmods.extend(valve.add_authed_mac(port_num, mac_str))

        if vlan_name:
            flowmods.extend(valve.add_dot1x_native_vlan(port_num, mac_str, vlan_name))

        return flowmods

    def _del_authenticated_flowmod(self, dot1x_port, valve, mac_str):
        """Return flowmods for deleting authentication flows from a port"""
        flowmods = []
        port_num = dot1x_port.number
        if dot1x_port.dot1x_acl:
            auth_acl, _ = self._get_acls(valve.dp)
            flowmods.extend(valve.del_port_acl(auth_acl, port_num, mac_str))
        else:
            flowmods.extend(valve.del_authed_mac(port_num, mac_str))

        flowmods.extend(valve.del_dot1x_native_vlan(port_num, mac_str))

        return flowmods

    def _add_unauthenticated_flowmod(self, dot1x_port, valve, mac_str=None):
        """Return flowmods default on a port"""
        flowmods = []
        if dot1x_port.dot1x_acl:
            _, noauth_acl = self._get_acls(valve.dp)
            flowmods.extend(valve.add_port_acl(noauth_acl, dot1x_port.number, mac_str))

        return flowmods

    def _del_unauthenticated_flowmod(self, dot1x_port, valve, mac_str=None):
        """Return flowmods for deleting default / unauthenticated flows from a port"""
        flowmods = []
        if dot1x_port.dot1x_acl:
            _, noauth_acl = self._get_acls(valve.dp)
            flowmods.extend(valve.del_port_acl(noauth_acl, dot1x_port.number, mac_str))

        return flowmods
