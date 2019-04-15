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
        self._send_flow_msgs = send_flow_msgs
        self._valves = None
        self.dot1x_speaker = None
        self.dot1x_intf = None
        self.mac_to_port = {}  # {"00:00:00:00:00:02" : (valve_0, port_1)}
        self.dp_id_to_valve_index = {}
        self.thread = None
        self.auth_acl_name = None
        self.noauth_acl_name = None

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

    def get_valve_and_port(self, port_id):
        """Finds the valve and port that this address corresponds to
        Args:
            port_id: is a macaddress string"""
        valve, port = self.mac_to_port[port_id]
        return (valve, port)

    def auth_handler(self, address, port_id, vlan_name, filter_id):
        """Callback for when a successful auth happens."""
        address_str = str(address)
        valve, dot1x_port = self.get_valve_and_port(port_id)
        self.logger.info(
            'Successful auth from MAC %s on %s' % (address_str, dot1x_port))
        self.metrics.inc_var('dp_dot1x_success', valve.dp.base_prom_labels())
        self.metrics.inc_var('port_dot1x_success', valve.dp.port_labels(dot1x_port.number))
        valve.dot1x_event({'AUTHENTICATION': {'dp_id': valve.dp.dp_id,
                                              'port': dot1x_port.number,
                                              'eth_src': address_str,
                                              'status': 'success'}})

        # Call acl manager for flowmods of ACL
        acl_manager = valve.acl_manager
        flowmods = []

        if dot1x_port.dot1x_acl:
            auth_acl = valve.dp.acls.get(self.auth_acl_name)
            noauth_acl = valve.dp.acls.get(self.noauth_acl_name)
            flowmods.extend(acl_manager.add_port_acl(auth_acl, dot1x_port, str(address)))
            flowmods.extend(acl_manager.del_port_acl(noauth_acl, dot1x_port))
        else:
            flowmods.extend(acl_manager.add_authed_mac(dot1x_port.number, str(address)))

        if flowmods:
            self._send_flow_msgs(valve, flowmods)

    def logoff_handler(self, address, port_id):
        """Callback for when an EAP logoff happens."""
        address_str = str(address)
        valve, dot1x_port = self.get_valve_and_port(port_id)
        self.logger.info(
            'Logoff from MAC %s on %s', address_str, dot1x_port)
        self.metrics.inc_var('dp_dot1x_logoff', valve.dp.base_prom_labels())
        self.metrics.inc_var('port_dot1x_logoff', valve.dp.port_labels(dot1x_port.number))
        valve.dot1x_event({'AUTHENTICATION': {'dp_id': valve.dp.dp_id,
                                              'port': dot1x_port.number,
                                              'eth_src': address_str,
                                              'status': 'logoff'}})

        acl_manager = valve.acl_manager
        flowmods = []

        if dot1x_port.dot1x_acl:
            auth_acl = valve.dp.acls.get(self.auth_acl_name)
            noauth_acl = valve.dp.acls.get(self.noauth_acl_name)

            flowmods.extend(acl_manager.del_port_acl(auth_acl, dot1x_port, str(address)))
            flowmods.extend(acl_manager.add_port_acl(noauth_acl, dot1x_port))
        else:
            flowmods.extend(valve.del_authed_mac(dot1x_port.number, str(address)))

        if flowmods:
            self._send_flow_msgs(valve, flowmods)

    def failure_handler(self, address, port_id):
        """Callback for when a EAP failure happens."""
        address_str = str(address)
        valve, dot1x_port = self.get_valve_and_port(port_id)
        self.logger.info(
            'Failure from MAC %s on %s, removing access', address_str, dot1x_port)
        self.metrics.inc_var('dp_dot1x_failure', valve.dp.base_prom_labels())
        self.metrics.inc_var('port_dot1x_failure', valve.dp.port_labels(dot1x_port.number))
        valve.dot1x_event({'AUTHENTICATION': {'dp_id': valve.dp.dp_id,
                                              'port': dot1x_port.number,
                                              'eth_src': address_str,
                                              'status': 'failure'}})

        acl_manager = valve.acl_manager
        flowmods = []

        if dot1x_port.dot1x_acl:
            auth_acl = valve.dp.acls.get(self.auth_acl_name)
            noauth_acl = valve.dp.acls.get(self.noauth_acl_name)

            flowmods.extend(acl_manager.del_port_acl(auth_acl, dot1x_port, str(address)))
            flowmods.extend(acl_manager.add_port_acl(noauth_acl, dot1x_port))
        else:
            flowmods.extend(valve.del_authed_mac(dot1x_port.number, str(address)))

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

    def nfv_sw_port_up(self, dp_id, dot1x_ports, nfv_sw_port, acl_manager):
        """Setup the dot1x forward port acls when the nfv_sw_port comes up.
        Args:
            dp_id (int):
            dot1x_ports (Iterable of Port objects):
            nfv_sw_port (Port):
            acl_manager (ValveAclManager):

        Returns:
            list of flowmods
        """
        self.dot1x_speaker.port_down(
            get_mac_str(self.dp_id_to_valve_index[dp_id], nfv_sw_port.number))
        valve = self._valves[dp_id]
        valve.dot1x_event({'PORT_UP': {'dp_id': valve.dp.dp_id,
                                       'port': nfv_sw_port.number,
                                       'port_type': 'nfv'}})
        ret = []
        for port in dot1x_ports:
            ret.extend(self.create_flow_pair(
                dp_id, port, nfv_sw_port, acl_manager))
        return ret

    def port_up(self, dp_id, dot1x_port, nfv_sw_port, acl_manager):
        """Setup the dot1x forward port acls.
        Args:
            dp_id (int):
            dot1x_port (Port):
            nfv_sw_port (Port):
            acl_manager (ValveAclManager):

        Returns:
            list of flowmods
        """
        mac_str = get_mac_str(self.dp_id_to_valve_index[dp_id], dot1x_port.number)

        self.dot1x_speaker.port_up(mac_str)

        valve = self._valves[dp_id]
        valve.dot1x_event({'PORT_UP': {'dp_id': valve.dp.dp_id,
                                       'port': dot1x_port.number,
                                       'port_type': 'supplicant'}})

        # Dealing with ACLs
        flowmods = []
        flowmods.extend(self.create_flow_pair(
            dp_id, dot1x_port, nfv_sw_port, acl_manager))

        if dot1x_port.dot1x_acl:
            noauth_acl = self._valves[dp_id].dp.acls.get(self.noauth_acl_name)
            flowmods.extend(
                acl_manager.add_port_acl(noauth_acl, dot1x_port)
            )

        return flowmods

    def create_flow_pair(self, dp_id, dot1x_port, nfv_sw_port, acl_manager):
        """Creates the pair of flows that redirects the eapol packets to/from
        the supplicant and nfv port

        Args:
            dp_id (int):
            dot1x_port (Port):
            nfv_sw_port (Port):
            acl_manager (ValveAclManager):

        Returns:
            list
        """
        if dot1x_port.running():
            valve_index = self.dp_id_to_valve_index[dp_id]
            mac = get_mac_str(valve_index, dot1x_port.number)
            return acl_manager.create_dot1x_flow_pair(
                dot1x_port, nfv_sw_port, mac)
        return []

    def _clean_up_acls(self, dp_id, dot1x_port, acl_manager, mac):
        '''Remove ACL flows from a port'''
        # Remove ACLS for Port
        flowmods = []

        if dot1x_port.dot1x_acl:
            auth_acl = self._valves[dp_id].dp.acls.get(self.auth_acl_name)
            noauth_acl = self._valves[dp_id].dp.acls.get(self.noauth_acl_name)

            if auth_acl:
                flowmods.extend(
                    acl_manager.del_port_acl(auth_acl, dot1x_port, mac)
                )

            if noauth_acl:
                flowmods.extend(
                    acl_manager.del_port_acl(noauth_acl, dot1x_port)
                )

        return flowmods

    def port_down(self, dp_id, dot1x_port, nfv_sw_port, acl_manager):
        """
        Remove the acls added by FaucetDot1x.get_port_acls
        Args:
            dp_id (int):
            dot1x_port (Port):
            nfv_sw_port (Port):
            acl_manager (ValveAclManager):

        Returns:
            list of flowmods
        """
        valve_index = self.dp_id_to_valve_index[dp_id]
        mac = get_mac_str(valve_index, dot1x_port.number)
        self.dot1x_speaker.port_down(get_mac_str(valve_index, dot1x_port.number))
        valve = self._valves[dp_id]
        valve.dot1x_event({'PORT_DOWN': {'dp_id': valve.dp.dp_id,
                                         'port': dot1x_port.number,
                                         'port_type': 'supplicant'}})

        flowmods = []
        flowmods.extend(self._clean_up_acls(dp_id, dot1x_port, acl_manager, mac))

        # Clear auth_mac
        flowmods.extend(acl_manager.del_authed_mac(dot1x_port.number))
        flowmods.extend(acl_manager.del_dot1x_flow_pair(dot1x_port, nfv_sw_port, mac))
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

        self.auth_acl_name = first_valve.dp.dot1x.get('auth_acl')
        self.noauth_acl_name = first_valve.dp.dot1x.get('noauth_acl')

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

            valve.dot1x_event({'ENABLED': {'dp_id': valve.dp.dp_id}})
