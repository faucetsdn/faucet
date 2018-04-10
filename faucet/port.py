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
from faucet import valve_of


class Port(Conf):
    """Stores state for ports, including the configuration."""

    name = None
    number = None
    dp_id = None
    description = None
    enabled = None
    permanent_learn = None
    unicast_flood = None
    mirror = None
    native_vlan = None
    tagged_vlans = [] # type: list
    acl_in = None
    acls_in = None
    stack = {} # type: dict
    max_hosts = None
    hairpin = None
    loop_protect = None
    output_only = None
    lldp_beacon = {} # type: dict
    op_status_reconf = None
    receive_lldp = None
    override_output_port = None

    dyn_learn_ban_count = 0
    dyn_phys_up = False
    dyn_last_lacp_pkt = None
    dyn_lacp_up = None
    dyn_lacp_updated_time = None
    dyn_last_ban_time = None
    dyn_last_lldp_beacon_time = None

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
        # If set, mirror packets from that port to this one.
        'native_vlan': None,
        # Set untagged VLAN on this port.
        'tagged_vlans': None,
        # Set tagged VLANs on this port.
        'acl_in': None,
        'acls_in': None,
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
        'output_only': False,
        # if True, all packets input from this port are dropped.
        'lldp_beacon': {},
        # LLDP beacon configuration for this port.
        'opstatus_reconf': True,
        # If True, configure pipeline if operational status of port changes.
        'receive_lldp': False,
        # If True, receive LLDP on this port.
        'override_output_port': None,
        # If set, packets are sent to this other port.
    }

    defaults_types = {
        'number': int,
        'name': str,
        'description': str,
        'enabled': bool,
        'permanent_learn': bool,
        'unicast_flood': bool,
        'mirror': (list, str, int),
        'native_vlan': (str, int),
        'tagged_vlans': list,
        'acl_in': (str, int),
        'acls_in': list,
        'stack': dict,
        'max_hosts': int,
        'hairpin': bool,
        'lacp': int,
        'loop_protect': bool,
        'output_only': bool,
        'lldp_beacon': dict,
        'opstatus_reconf': bool,
        'receive_lldp': bool,
        'override_output_port': (str, int),
    }

    stack_defaults_types = {
        'dp': str,
        'port': (str, int),
    }

    lldp_beacon_defaults_types = {
        'enable': bool,
        'org_tlvs': list,
        'system_name': str,
        'port_descr': str,
    }

    lldp_org_tlv_defaults_types = {
        'oui': (int, bytearray),
        'subtype': (int, bytearray),
        'info': (str, bytearray)
    }

    def __init__(self, _id, dp_id, conf=None):
        super(Port, self).__init__(_id, dp_id, conf)
        self.dyn_phys_up = False

        # If the port is mirrored convert single attributes to a array
        if self.mirror and not isinstance(self.mirror, list):
            self.mirror = [self.mirror]

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
        assert isinstance(self.number, int) and self.number > 0 and not valve_of.ignore_port(self.number), (
            'Port number invalid: %s' % self.number)
        if self.mirror:
            assert not self.tagged_vlans and not self.native_vlan, (
                'mirror port %s cannot have any VLANs assigned' % self)
        if self.stack:
            self._check_conf_types(self.stack, self.stack_defaults_types)
            for stack_config in list(self.stack_defaults_types.keys()):
                assert stack_config in self.stack, 'stack %s must be defined' % stack_config
        if self.lldp_beacon:
            self._check_conf_types(
                self.lldp_beacon, self.lldp_beacon_defaults_types)
            self.lldp_beacon = self._set_unknown_conf(
                self.lldp_beacon, self.lldp_beacon_defaults_types)
            if self.lldp_beacon_enabled():
                if self.lldp_beacon['port_descr'] is None:
                    self.lldp_beacon['port_descr'] = self.description

                org_tlvs = []
                for org_tlv in self.lldp_beacon['org_tlvs']:
                    self._check_conf_types(org_tlv, self.lldp_org_tlv_defaults_types)
                    assert len(org_tlv) == len(self.lldp_org_tlv_defaults_types), (
                        'missing org_tlv config')
                    if not isinstance(org_tlv['info'], bytearray):
                        try:
                            org_tlv['info'] = bytearray.fromhex(
                                org_tlv['info']) # pytype: disable=missing-parameter
                        except ValueError:
                            org_tlv['info'] = org_tlv['info'].encode('utf-8')
                    if not isinstance(org_tlv['oui'], bytearray):
                        org_tlv['oui'] = bytearray.fromhex(
                            '%6.6x' % org_tlv['oui']) # pytype: disable=missing-parameter
                    org_tlvs.append(org_tlv)
                self.lldp_beacon['org_tlvs'] = org_tlvs
        if self.acl_in and self.acls_in:
            assert False, 'found both acl_in and acls_in, use only acls_in'
        if self.acl_in and not isinstance(self.acl_in, list):
            self.acls_in = [self.acl_in,]
            self.acl_in = None
        if self.acls_in:
            for acl in self.acls_in:
                assert isinstance(acl, (int, str)), 'acl names must be int or'

    def finalize(self):
        assert self.vlans() or self.stack or self.output_only, (
            '%s must have a VLAN, be a stack port, or have output_only: True' % self)
        assert not (self.vlans() and self.stack), (
            '%s cannot have stack and VLANs on same port' % self)
        if self.native_vlan:
            assert self.native_vlan not in self.tagged_vlans, (
                'cannot have same native and tagged VLAN on same port')
        super(Port, self).finalize()

    def running(self):
        """Return True if port enabled and up."""
        return self.enabled and self.dyn_phys_up

    def to_conf(self):
        result = super(Port, self).to_conf()
        if 'stack' in result and result['stack'] is not None:
            result['stack'] = {}
            for stack_config in list(self.stack_defaults_types.keys()):
                result['stack'][stack_config] = self.stack[stack_config]
        return result

    def vlans(self):
        """Return list of all VLANs this port is in."""
        if self.native_vlan is not None:
            return [self.native_vlan] + self.tagged_vlans
        return self.tagged_vlans

    def hosts(self, vlans=None):
        """Return all host cache entries this port has learned (on all or specified VLANs)."""
        if vlans is None:
            vlans = self.vlans()
        hosts = []
        for vlan in vlans:
            hosts.extend([entry for entry in list(vlan.cached_hosts_on_port(self))])
        return hosts

    def hosts_count(self, vlans=None):
        """Return count of all hosts this port has learned (on all or specified VLANs)."""
        if vlans is None:
            vlans = self.vlans()
        hosts_count = 0
        for vlan in vlans:
            hosts_count += vlan.cached_hosts_count_on_port(self)
        return hosts_count

    def lldp_beacon_enabled(self):
        """Return True if LLDP beacon enabled on this port."""
        return self.lldp_beacon and self.lldp_beacon.get('enable', False)

    def mirror_actions(self):
        """Return OF actions to mirror this port."""
        if self.mirror is not None:
            return [valve_of.output_port(mirror_port) for mirror_port in self.mirror]
        return []
