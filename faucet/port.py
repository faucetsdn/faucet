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
from faucet.valve_of import ignore_port


class Port(Conf):
    """Stores state for ports, including the configuration.

Interface Configuration

Interface configuration is found under the 'interfaces' configuration block
within the config for a datapath. IE:
/dps/<dp name or dp_id>/interfaces/<port name or ofp port number>/

The defaults for groups of interfaces can be configured under:
/dps/<dp name or dp_id>/interface-ranges/<interface range specification>

<interface range specification> is a string containing a comma separated list
of port numbers, port names or port ranges (in the form of 2 integers separated
by a dash).

The following elements can be configured for each port:

 * number (int): the OFP port number for this port. Defaults to the
    configuration key.
 * name (string): a name to reference this port by. Defaults to the
    configuration key.
 * description (str): an arbitrary description for this port.
 * enabled (bool): Allow packets to be forwarded through this port. Defaults to
    True.
 * native_vlan (int): The vlan associated with untagged packets arriving and
    leaving this interface.
 * tagged_vlans (list of ints): The vlans associated with tagged packets
    arriving and leaving this interfaces.
 * acl_in (int or string): The acl that should be applied to all packets
    arriving on this port.
 * permanent_learn (bool): When True Faucet will only learn the first MAC
    address on this interface. All packets with an ethernet src address not
    equal to that MAC address will be dropped.
 * unicast_flood (bool): If False unicast packets will not be flooded to this
    port. Defaults to True.
 * mirror (str or int): Mirror all packets recieved and transmitted on this
    port to the port specified (by name or by port number)
 * max_hosts (int): the maximum number of mac addresses that can be learnt on
    this port. Defaults to 255
 * hairpin (bool): If True it allows packets arriving on this port to be output
    to this port. This is necessary to allow routing between two vlans on this
    port, or for use with a WIFI radio port. Defaults to False.
 * lacp (int): If not 0 this will enable experimental passive LACP support for
    this port. The value supplied will be the LAG ID. Defaults to 0.
 * loop_protect (bool): Experimental loop protection. TODO: explain how this
    works.

Further configuration sublevels can be configured as follows:

 * stack:

    * dp (str or int): the name or dp_id of the dp connected to this port
    * port (str or int): the name or port number of the port on the remote dp
        connected to this port
    """

    name = None
    number = None
    dp_id = None
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

    def __init__(self, _id, dp_id, conf=None):
        super(Port, self).__init__(_id, dp_id, conf)
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

    def check_config(self):
        super(Port, self).check_config()
        assert isinstance(self.number, int) and self.number > 0 and not ignore_port(self.number), (
            'Port number invalid: %s' % self.number)

    def finalize(self):
        assert self.vlans() or self.stack, '%s must have a VLAN or be a stack port' % self
        assert not (self.vlans() and self.stack), '%s cannot have stack and VLANs on same port' % self
        super(Port, self).finalize()

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
