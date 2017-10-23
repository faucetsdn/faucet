"""Port configuration."""

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
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from faucet.conf import Conf


class Port(Conf):
    """Implement FAUCET configuration for a port."""

    name = None
    number = None
    enabled = None
    permanent_learn = None
    unicast_flood = None
    mirror = None
    mirror_destination = None
    native_vlan = None
    tagged_vlans = []
    acl_in = None
    stack = {}
    max_hosts = None
    hairpin = None
    loop_protect = None
    dyn_learn_ban_count = 0
    dyn_phys_up = False
    dyn_last_lacp_pkt = None
    dyn_lacp_up = None
    dyn_lacp_updated_time = None
    dyn_last_ban_time = None

    defaults = {
        'number': None,
        'name': None,
        'description': None,
        'enabled': True,
        'permanent_learn': False,
        # if True, a host once learned on this port cannot be learned on another port.
        'unicast_flood': True,
        # if True, do classical unicast flooding on this port (False floods ND/ARP/bcast only).
        'mirror': None,
        'mirror_destination': False,
        'native_vlan': None,
        # Set untagged VLAN on this port.
        'tagged_vlans': None,
        # Set tagged VLANs on this port.
        'acl_in': None,
        # ACL for input on this port.
        'stack': None,
        # Configure a stack peer on this port.
        'max_hosts': 255,
        # maximum number of hosts
        'hairpin': False,
        # if True, then switch between hosts on this port (eg WiFi radio).
        'lacp': 0,
        # if non 0 (LAG ID), experimental LACP support enabled on this port.
        'loop_protect': False,
        # if True, do simple loop protection on this port.
    }

    defaults_types = {
        'number': int,
        'name': str,
        'description': str,
        'enabled': bool,
        'permanent_learn': bool,
        'unicast_flood': bool,
        'mirror': (str, int),
        'mirror_destination': bool,
        'native_vlan': (str, int),
        'tagged_vlans': list,
        'acl_in': (str, int),
        'stack': dict,
        'max_hosts': int,
        'hairpin': bool,
        'lacp': int,
        'loop_protect': bool,
    }

    def __init__(self, _id, conf=None):
        super(Port, self).__init__(_id, conf)
        self.dyn_phys_up = False

    def __str__(self):
        return 'Port %u' % self.number

    def __repr__(self):
        return self.__str__()

    def set_defaults(self):
        super(Port, self).set_defaults()
        self._set_default('number', self._id)
        self._set_default('name', str(self._id))
        self._set_default('description', self.name)
        self._set_default('tagged_vlans', [])

    def running(self):
        return self.enabled and self.dyn_phys_up

    def to_conf(self):
        result = super(Port, self).to_conf()
        if 'stack' in result and result['stack'] is not None:
            if 'dp' in self.stack and 'port' in self.stack:
                result['stack'] = {
                    'dp': str(self.stack['dp']),
                    'port': str(self.stack['port'])
                }
        return result

    def vlans(self):
        """Return list of all VLANs this port is in."""
        if self.native_vlan is not None:
            return [self.native_vlan] + self.tagged_vlans
        return self.tagged_vlans

    def hosts(self, vlans=None):
        """Return all hosts this port has learned (on all or specified VLANs)."""
        if vlans is None:
            vlans = self.vlans()
        hosts = []
        for vlan in vlans:
            hosts.extend([entry.eth_src for entry in list(vlan.cached_hosts_on_port(self))])
        return hosts
