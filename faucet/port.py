"""Port configuration."""

# Copyright (C) 2015 Brad Cowie, Christopher Lorier and Joe Stringer.
# Copyright (C) 2015 Research and Education Advanced Network New Zealand Ltd.
# Copyright (C) 2015--2018 The Contributors
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

from faucet.conf import Conf, InvalidConfigError, test_config_condition
from faucet import valve_of

STACK_STATE_ADMIN_DOWN = 0
STACK_STATE_INIT = 1
STACK_STATE_DOWN = 2
STACK_STATE_UP = 3


class Port(Conf):
    """Stores state for ports, including the configuration."""

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
        # if True, then switch unicast and flood between hosts on this port (eg WiFi radio).
        'hairpin_unicast': False,
        # if True, then switch unicast between hosts on this port (eg WiFi radio).
        'lacp': 0,
        # if non 0 (LAG ID), experimental LACP support enabled on this port.
        'lacp_active': False,
        # experimental active LACP
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
        'max_lldp_lost': 3,
        # threshold before marking a stack port as down
        'dot1x': False,
        # If true, block this port until a successful 802.1x auth
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
        'hairpin_unicast': bool,
        'lacp': int,
        'lacp_active': bool,
        'loop_protect': bool,
        'output_only': bool,
        'lldp_beacon': dict,
        'opstatus_reconf': bool,
        'receive_lldp': bool,
        'override_output_port': (str, int),
        'dot1x': bool,
        'max_lldp_lost': int,
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
        self.acl_in = None
        self.acls_in = None
        self.description = None
        self.dot1x = None
        self.dp_id = None
        self.enabled = None
        self.hairpin = None
        self.hairpin_unicast = None
        self.lacp = None
        self.lacp_active = None
        self.loop_protect = None
        self.max_hosts = None
        self.max_lldp_lost = None
        self.mirror = None
        self.name = None
        self.native_vlan = None
        self.number = None
        self.op_status_reconf = None
        self.opstatus_reconf = None
        self.output_only = None
        self.override_output_port = None
        self.permanent_learn = None
        self.receive_lldp = None
        self.stack = {}
        self.unicast_flood = None

        self.dyn_lacp_up = None
        self.dyn_lacp_updated_time = None
        self.dyn_last_ban_time = None
        self.dyn_last_lacp_pkt = None
        self.dyn_last_lldp_beacon_time = None
        self.dyn_learn_ban_count = 0
        self.dyn_phys_up = False
        self.dyn_stack_current_state = STACK_STATE_DOWN
        self.dyn_stack_probe_info = {}

        self.tagged_vlans = []
        self.lldp_beacon = {}
        super(Port, self).__init__(_id, dp_id, conf)

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
        test_config_condition(not (isinstance(self.number, int) and self.number > 0 and (
            not valve_of.ignore_port(self.number))), ('Port number invalid: %s' % self.number))
        test_config_condition(
            self.hairpin and self.hairpin_unicast,
            'Cannot have both hairpin and hairpin_unicast enabled')
        if self.dot1x:
            test_config_condition(self.number > 255, (
                '802.1x not supported on ports > 255'))
        if self.mirror:
            test_config_condition(self.tagged_vlans or self.native_vlan, (
                'mirror port %s cannot have any VLANs assigned' % self))
        if self.stack:
            self._check_conf_types(self.stack, self.stack_defaults_types)
            for stack_config in list(self.stack_defaults_types.keys()):
                test_config_condition(stack_config not in self.stack, (
                    'stack %s must be defined' % stack_config))
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
                    test_config_condition(len(org_tlv) != len(self.lldp_org_tlv_defaults_types), (
                        'missing org_tlv config'))
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
            raise InvalidConfigError('found both acl_in and acls_in, use only acls_in')
        if self.acl_in and not isinstance(self.acl_in, list):
            self.acls_in = [self.acl_in,]
            self.acl_in = None
        if self.acls_in:
            for acl in self.acls_in:
                test_config_condition(not isinstance(acl, (int, str)),
                                      'ACL names must be int or str')

    def finalize(self):
        test_config_condition(not (self.vlans() or self.stack or self.output_only), (
            '%s must have a VLAN, be a stack port, or have output_only: True' % self))
        test_config_condition(self.vlans() and self.stack, (
            '%s cannot have stack and VLANs on same port' % self))
        if self.native_vlan:
            test_config_condition(self.native_vlan in self.tagged_vlans, (
                'cannot have same native and tagged VLAN on same port'))
        self.tagged_vlans = tuple(self.tagged_vlans)
        super(Port, self).finalize()

    def running(self):
        """Return True if port enabled and up."""
        return self.enabled and self.dyn_phys_up

    def to_conf(self):
        result = super(Port, self).to_conf()
        if result is not None:
            if 'stack' in result and result['stack']:
                result['stack'] = {}
                for stack_config in list(self.stack_defaults_types.keys()):
                    result['stack'][stack_config] = self.stack[stack_config]
            if self.native_vlan is not None:
                result['native_vlan'] = self.native_vlan.name
            result['tagged_vlans'] = [vlan.name for vlan in self.tagged_vlans]
        return result

    def vlans(self):
        """Return all VLANs this port is in."""
        if self.native_vlan is not None:
            return (self.native_vlan,) + tuple(self.tagged_vlans)
        return tuple(self.tagged_vlans)

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

    def is_stack_up(self):
        """Return True if port is in UP state."""
        return self.dyn_stack_current_state == STACK_STATE_UP

    def is_stack_down(self):
        """Return True if port is in DOWN state."""
        return self.dyn_stack_current_state == STACK_STATE_DOWN

    def is_stack_admin_down(self):
        """Return True if port is in ADMIN_DOWN state."""
        return self.dyn_stack_current_state == STACK_STATE_ADMIN_DOWN

    def is_stack_init(self):
        """Return True if port is in INIT state."""
        return self.dyn_stack_current_state == STACK_STATE_INIT

    def stack_up(self):
        """Change the current stack state to UP."""
        self.dyn_stack_current_state = STACK_STATE_UP

    def stack_down(self):
        """Change the current stack state to DOWN."""
        self.dyn_stack_current_state = STACK_STATE_DOWN

    def stack_admin_down(self):
        """Change the current stack state to ADMIN_DOWN."""
        self.dyn_stack_current_state = STACK_STATE_ADMIN_DOWN

    def stack_init(self):
        """Change the current stack state to INIT_DOWN."""
        self.dyn_stack_current_state = STACK_STATE_INIT
