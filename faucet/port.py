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

try:
    from conf import Conf
except ImportError:
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
    learn_ban_count = 0

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
    }

    def __init__(self, _id, conf=None):
        if conf is None:
            conf = {}
        self._id = _id
        self.update(conf)
        self.set_defaults()
        self.dyn_phys_up = False

    def set_defaults(self):
        for key, value in list(self.defaults.items()):
            self._set_default(key, value)
        self._set_default('number', self._id)
        self._set_default('name', str(self._id))
        self._set_default('description', self.name)
        self._set_default('tagged_vlans', [])

    @property
    def phys_up(self):
        return self.dyn_phys_up

    @phys_up.setter
    def phys_up(self, status):
        self.dyn_phys_up = status

    def running(self):
        return self.enabled and self.phys_up

    def to_conf(self):
        result = super(Port, self).to_conf()
        if 'stack' in result and result['stack'] is not None:
            if 'dp' in self.stack and 'port' in self.stack:
                result['stack'] = {
                    'dp': str(self.stack['dp']),
                    'port': str(self.stack['port'])
                }
        return result

    def __str__(self):
        return 'Port %u' % self.number

    def __repr__(self):
        return self.__str__()
