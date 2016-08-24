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

from conf import Conf
from vlan import VLAN
from port import Port


class DP(Conf):
    """Object to hold the configuration for a faucet controlled datapath."""

    acls = None
    vlans = None
    ports = None
    running = False
    influxdb_stats = False

    # Values that are set to None will be set using set_defaults
    # they are included here for testing and informational purposes
    defaults = {
        'dp_id': None,
        # Name for this dp, used for stats reporting and configuration
        'name': None,
        'table_offset': 0,
        # The table for internally associating vlans
        'vlan_table': None,
        'acl_table': None,
        'eth_src_table': None,
        'ipv4_fib_table': None,
        'ipv6_fib_table': None,
        'eth_dst_table': None,
        'flood_table': None,
        # How much to offset default priority by
        'priority_offset': 0,
        # Some priority values
        'lowest_priority': None,
        'low_priority': None,
        'high_priority': None,
        'highest_priority': None,
        # Identification cookie value to allow for multiple controllers to
        # control the same datapath
        'cookie': 1524372928,
        # inactive MAC timeout
        'timeout': 300,
        # description, strictly informational
        'description': None,
        # The hardware maker (for chosing an openflow driver)
        'hardware': 'Open vSwitch',
        # ARP and neighbor timeout (seconds)
        'arp_neighbor_timeout': 500,
        # OF channel log
        'ofchannel_log': None,
        }

    def __init__(self, _id, conf):
        self._id = _id
        self.update(conf)
        self.set_defaults()
        self.acls = {}
        self.vlans = {}
        self.ports = {}
        self.mirror_from_port = {}
        self.acl_in = {}

    def sanity_check(self):
        # TODO: this shouldnt use asserts
        assert 'dp_id' in self.__dict__
        assert isinstance(self.dp_id, (int, long))
        for vid, vlan in self.vlans.iteritems():
            assert isinstance(vid, int)
            assert isinstance(vlan, VLAN)
            assert all(isinstance(p, Port) for p in vlan.get_ports())
        for portnum, port in self.ports.iteritems():
            assert isinstance(portnum, int)
            assert isinstance(port, Port)

    def set_defaults(self):
        for key, value in self.defaults.iteritems():
            self._set_default(key, value)
        # fix special cases
        self._set_default('dp_id', self._id)
        self._set_default('name', str(self._id))
        self._set_default('vlan_table', self.table_offset)
        self._set_default('acl_table', self.table_offset + 1)
        self._set_default('eth_src_table', self.acl_table + 1)
        self._set_default('ipv4_fib_table', self.eth_src_table + 1)
        self._set_default('ipv6_fib_table', self.ipv4_fib_table + 1)
        self._set_default('eth_dst_table', self.ipv6_fib_table + 1)
        self._set_default('flood_table', self.eth_dst_table + 1)
        self._set_default('lowest_priority', self.priority_offset)
        self._set_default('low_priority', self.priority_offset + 9000)
        self._set_default('high_priority', self.low_priority + 1)
        self._set_default('highest_priority', self.high_priority + 98)
        self._set_default('description', self.name)

    def add_acl(self, acl_ident, acl_conf=None):
        if acl_conf is not None:
            self.acls[acl_ident] = [x['rule'] for x in acl_conf]

    def add_port(self, port):
        port_num = port.number
        self.ports[port_num] = port
        if port.mirror is not None:
            self.mirror_from_port[port.mirror] = port.number
            # other configuration entries ignored
            return
        if port.acl_in is not None:
            self.acl_in[port_num] = port.acl_in

    def add_vlan(self, vlan):
        self.vlans[vlan.vid] = vlan

    def get_native_vlan(self, port_num):
        if port_num not in self.ports:
            return None

        port = self.ports[port_num]

        for vlan in self.vlans.values():
            if port in vlan.untagged:
                return vlan

        return None

    def __str__(self):
        return self.name
