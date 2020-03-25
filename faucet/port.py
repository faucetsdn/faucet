"""Port configuration."""

# Copyright (C) 2015 Brad Cowie, Christopher Lorier and Joe Stringer.
# Copyright (C) 2015 Research and Education Advanced Network New Zealand Ltd.
# Copyright (C) 2015--2019 The Contributors
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
import netaddr

STACK_STATE_ADMIN_DOWN = 0
STACK_STATE_INIT = 1
STACK_STATE_BAD = 2
STACK_STATE_UP = 3
STACK_STATE_GONE = 4
STACK_STATE_NONE = -1

# LACP not configured
LACP_ACTOR_NOTCONFIGURED = -1
# Not receiving packets from the actor & port is down
LACP_ACTOR_NONE = 0
# Not receiving packets from the actor & port is up
LACP_ACTOR_INIT = 1
# Receiving LACP packets with sync bit set
LACP_ACTOR_UP = 3
# LACP actor is not sending LACP with sync bit set
LACP_ACTOR_NOSYNC = 5
LACP_ACTOR_DISPLAY_DICT = {
    LACP_ACTOR_NOTCONFIGURED: 'NOT_CONFIGURED',
    LACP_ACTOR_NONE: 'NONE',
    LACP_ACTOR_INIT: 'INITIALIZING',
    LACP_ACTOR_UP: 'UP',
    LACP_ACTOR_NOSYNC: 'NO_SYNC'
}

# LACP is not configured
LACP_PORT_NOTCONFIGURED = -1
# Port is not a LACP port on the nominated DP
LACP_PORT_UNSELECTED = 1
# Port is a LACP port on the nominated DP, will send/receive
LACP_PORT_SELECTED = 2
# Port is a LACP port that is in standby
LACP_PORT_STANDBY = 3
LACP_PORT_DISPLAY_DICT = {
    LACP_PORT_NOTCONFIGURED: 'NOT_CONFIGURED',
    LACP_PORT_UNSELECTED: 'UNSELECTED',
    LACP_PORT_SELECTED: 'SELECTED',
    LACP_PORT_STANDBY: 'STANDBY'
}

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
        'lacp_collect_and_distribute': False,
        # if true, forces LACP port to collect and distribute when syncing with the peer.
        'lacp_unselected': False,
        # if true, forces LACP port to be in unselected state
        'lacp_selected': False,
        # if true, forces LACP port to be in the selected state
        'lacp_standby': False,
        # if true, forces LACP port to be in the standby state
        'lacp_passthrough': None,
        # If set, fail the lacp on this port if any of the peer ports are down.
        'lacp_resp_interval': 1,
        # Min time since last LACP response. Used to control rate of response for LACP
        'loop_protect': False,
        # if True, do simple (host/access port) loop protection on this port.
        'loop_protect_external': False,
        # if True, do external (other switch) loop protection on this port.
        'output_only': False,
        # if True, all packets input from this port are dropped.
        'lldp_beacon': {},
        # LLDP beacon configuration for this port.
        'opstatus_reconf': True,
        # If True, configure pipeline if operational status of port changes.
        'receive_lldp': False,
        # If True, receive LLDP on this port.
        'lldp_peer_mac': None,
        # If set, validates src MAC address of incoming LLDP packets
        'max_lldp_lost': 3,
        # threshold before marking a stack port as down
        'dot1x': False,
        # If true, block this port until a successful 802.1x auth
        'dot1x_acl': False,
        # If true, expects authentication and default ACLs for 802.1x auth
        'dot1x_mab': False,
        # If true, allows Mac Auth Bypass on port (NOTE: this is less secure as MACs can be spoofed)
        'dot1x_dyn_acl': False,
        # If true, expects authentication and ACLs with dot1x_assigned flag set
        'restricted_bcast_arpnd': False,
        # If true, this port cannot send non-ARP/IPv6 ND broadcasts to other restricted_bcast_arpnd ports.
        'coprocessor': {},
        # If defined, this port is attached to a packet coprocessor.
        'count_untag_vlan_miss': {},
        # If defined, this port will explicitly count unconfigured native VLAN packets.
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
        'lacp_collect_and_distribute': bool,
        'lacp_unselected': bool,
        'lacp_selected': bool,
        'lacp_standby': bool,
        'lacp_passthrough': list,
        'lacp_resp_interval': int,
        'loop_protect': bool,
        'loop_protect_external': bool,
        'output_only': bool,
        'lldp_beacon': dict,
        'opstatus_reconf': bool,
        'receive_lldp': bool,
        'lldp_peer_mac': str,
        'dot1x': bool,
        'dot1x_acl': bool,
        'dot1x_mab': bool,
        'dot1x_dyn_acl': bool,
        'max_lldp_lost': int,
        'restricted_bcast_arpnd': bool,
        'coprocessor': dict,
        'count_untag_vlan_miss': bool,
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

    coprocessor_defaults_types = {
        'strategy': str,
        'vlan_vid_base': int,
    }

    def __init__(self, _id, dp_id, conf=None):
        self.acl_in = None
        self.acls_in = None
        self.description = None
        self.dot1x = None
        self.dot1x_acl = None
        self.dot1x_mab = None
        self.dot1x_dyn_acl = None
        self.dp_id = None
        self.enabled = None
        self.hairpin = None
        self.hairpin_unicast = None
        self.lacp = None
        self.lacp_active = None
        self.lacp_collect_and_distribute = None
        self.lacp_unselected = None
        self.lacp_selected = None
        self.lacp_standby = None
        self.lacp_passthrough = None
        self.lacp_resp_interval = None
        self.loop_protect = None
        self.loop_protect_external = None
        self.max_hosts = None
        self.max_lldp_lost = None
        self.mirror = None
        self.name = None
        self.native_vlan = None
        self.number = None
        self.opstatus_reconf = None
        self.output_only = None
        self.permanent_learn = None
        self.receive_lldp = None
        self.lldp_peer_mac = None
        self.stack = {}
        self.unicast_flood = None
        self.restricted_bcast_arpnd = None
        self.coprocessor = {}
        self.count_untag_vlan_miss = None

        self.dyn_dot1x_native_vlan = None
        self.dyn_lacp_up = None
        self.dyn_lacp_updated_time = None
        self.dyn_lacp_last_resp_time = None
        self.dyn_last_ban_time = None
        self.dyn_last_lacp_pkt = None
        self.dyn_last_lldp_beacon_time = None
        self.dyn_lldp_beacon_recv_state = None
        self.dyn_lldp_beacon_recv_time = None
        self.dyn_learn_ban_count = 0
        self.dyn_phys_up = False
        self.dyn_update_time = None
        self.dyn_stack_current_state = STACK_STATE_NONE
        self.dyn_lacp_port_selected = LACP_PORT_NOTCONFIGURED
        self.dyn_lacp_actor_state = LACP_ACTOR_NOTCONFIGURED
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

    def stack_descr(self):
        """"Return stacking annotation if this is a stacking port."""
        if self.stack:
            return 'remote DP %s %s' % (self.stack['dp'].name, self.stack['port'])
        return ''

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
        non_vlan_options = {'stack', 'mirror', 'coprocessor', 'output_only'}
        vlan_agnostic_options = {'enabled', 'number', 'name', 'description', 'max_lldp_lost'}
        vlan_port = self.tagged_vlans or self.native_vlan
        non_vlan_port_options = {option for option in non_vlan_options if getattr(self, option)}
        test_config_condition(
            vlan_port and non_vlan_port_options,
            'cannot have VLANs configured on non-VLAN ports: %s' % self)
        if self.output_only:
            test_config_condition(
                not non_vlan_port_options.issubset({'mirror', 'output_only'}),
                'output_only can only coexist with mirror option on same port %s' % self)
        elif self.mirror:
            test_config_condition(
                not non_vlan_port_options.issubset({'mirror', 'coprocessor'}),
                'coprocessor can only coexist with mirror option on same port %s' % self)
        else:
            test_config_condition(
                len(non_vlan_port_options) > 1,
                'cannot have multiple non-VLAN port options %s on same port: %s' % (
                    non_vlan_port_options, self))
        if non_vlan_port_options:
            for key, default_val in self.defaults.items():
                if key in vlan_agnostic_options or key in non_vlan_port_options:
                    continue
                if key.startswith('acl') and self.stack:
                    continue
                val = getattr(self, key)
                test_config_condition(
                    val != default_val and val,
                    'Cannot have VLAN option %s: %s on non-VLAN port %s' % (key, val, self))
        test_config_condition(
            self.hairpin and self.hairpin_unicast,
            'Cannot have both hairpin and hairpin_unicast enabled')
        if self.dot1x:
            test_config_condition(self.number > 65535, (
                '802.1x not supported on ports > 65535'))
        if self.dot1x_acl:
            test_config_condition(not self.dot1x, (
                '802.1x_ACL requires dot1x to be enabled also'))
        if self.dot1x_mab:
            test_config_condition(not self.dot1x, (
                '802.1x_MAB requires dot1x to be enabled on the port also'))
            test_config_condition(self.dot1x_dyn_acl, (
                '802.1x_ACL cannot be used with 802.1x_DYN_ACL'))
        if self.dot1x_dyn_acl:
            test_config_condition(not self.dot1x, (
                '802.1x_DYN_ACL requires dot1x to be enabled also'))
            test_config_condition(self.dot1x_acl, (
                '802.1x_DYN_ACL cannot be used with 802.1x_ACL'))
            test_config_condition(self.dot1x_acl, (
                '802.1x_DYN_ACL cannot be used with 802.1x_MAB'))
        if self.coprocessor:
            self._check_conf_types(self.coprocessor, self.coprocessor_defaults_types)
            test_config_condition(
                self.coprocessor.get('strategy', None) != 'vlan_vid',
                'coprocessor only supports vlan_vid strategy')
            self.coprocessor['vlan_vid_base'] = self.coprocessor.get('vlan_vid_base', 1000)
        if self.stack:
            self._check_conf_types(self.stack, self.stack_defaults_types)
            for stack_config in list(self.stack_defaults_types.keys()):
                test_config_condition(stack_config not in self.stack, (
                    'stack %s must be defined' % stack_config))
            # LLDP always enabled for stack ports.
            self.receive_lldp = True
            if not self.lldp_beacon_enabled():
                self.lldp_beacon.update({'enable': True})
        if self.lacp_resp_interval is not None:
            test_config_condition(
                self.lacp_resp_interval > 65535 or self.lacp_resp_interval < 0.3,
                ('interval must be at least 0.3 and less than 65536'))
        if self.lldp_peer_mac:
            test_config_condition(not netaddr.valid_mac(self.lldp_peer_mac), (
                'invalid MAC address %s' % self.lldp_peer_mac))
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
        test_config_condition(
            self.acl_in and self.acls_in,
            'Found both acl_in and acls_in, use only acls_in')
        if self.acl_in and not isinstance(self.acl_in, list):
            self.acls_in = [self.acl_in,]
            self.acl_in = None
        if self.acls_in:
            for acl in self.acls_in:
                test_config_condition(not isinstance(acl, (int, str)),
                                      'ACL names must be int or str')
        lacp_options = [self.lacp_selected, self.lacp_unselected, self.lacp_standby]
        test_config_condition(
            lacp_options.count(True) > 1,
            'Cannot force multiple LACP port selection states')

    def finalize(self):
        if self.native_vlan:
            test_config_condition(self.native_vlan in self.tagged_vlans, (
                'cannot have same native and tagged VLAN on same port'))
        self.tagged_vlans = tuple(self.tagged_vlans)
        super(Port, self).finalize()

    def running(self):
        """Return True if port enabled and up."""
        return self.enabled and self.dyn_phys_up

    def vlans(self):
        """Return all VLANs this port is in."""
        if self.native_vlan is not None and self.dyn_dot1x_native_vlan is not None:
            return (self.native_vlan,) + (self.dyn_dot1x_native_vlan,) + tuple(self.tagged_vlans)
        if self.dyn_dot1x_native_vlan is not None:
            return (self.dyn_dot1x_native_vlan,) + tuple(self.tagged_vlans)
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

    def non_stack_forwarding(self):
        """Returns True if port is not-stacking and, and able to forward packets."""
        if self.stack:
            return False
        if not self.dyn_phys_up:
            return False
        if self.lacp and not self.dyn_lacp_up:
            return False
        return True

    # LACP functions
    def lacp_actor_update(self, lacp_up, now=None, lacp_pkt=None, cold_start=False):
        """
        Update the LACP actor state
        Args:
            lacp_up (bool): The intended LACP/port state
            now (float): Current time
            lacp_pkt (PacketMeta): Received LACP packet
            cold_start (bool): Whether the port is being cold started
        Returns:
            current LACP actor state
        """
        self.dyn_lacp_up = 1 if lacp_up else 0
        self.dyn_lacp_updated_time = now
        self.dyn_last_lacp_pkt = lacp_pkt
        if cold_start:
            # Cold starting, so revert to unconfigured LACP state
            self.actor_notconfigured()
        elif not self.running():
            # Phys not up so we do not initialize actor states
            self.actor_none()
        elif not lacp_pkt:
            # Intialize states
            self.actor_init()
        else:
            # Packets received from actor
            if lacp_up:
                # Receiving packets & LACP is UP
                self.actor_up()
            else:
                # Receiving packets but LACP sync bit is not set
                self.actor_nosync()
        return self.actor_state()

    def lacp_port_update(self, selected, cold_start=False):
        """
        Updates the LACP port selection state
        Args:
            selected (bool): Whether the port's DPID is the selected one
            cold_start (bool): Whether the port is being cold started
        Returns
            current lacp port state
        """
        if cold_start:
            # Cold starting, so revert to unconfigured state
            self.deconfigure_port()
        elif self.lacp_selected:
            # Can configure LACP port to be forced SELECTED
            self.select_port()
        elif self.lacp_standby:
            # Can configure LACP port to be forced STANDBY
            self.standby_port()
        elif self.lacp_unselected:
            # Can configure LACP port to be force UNSELECTED
            self.deselect_port()
        else:
            if selected:
                # Belongs on chosen DP for LAG, so SELECT port
                self.select_port()
            else:
                # Doesn't belong on chosen DP for LAG, DESELECT port
                self.deselect_port()
        return self.lacp_port_state()

    def get_lacp_flags(self):
        """
        Get the LACP flags for the state the port is in
        Return sync, collecting, distributing flag values
        """
        if self.lacp_collect_and_distribute:
            return 1, 1, 1
        if self.is_port_selected():
            return 1, 1, 1
        if self.is_port_standby():
            return 1, 0, 0
        return 0, 0, 0

    # LACP ACTOR STATES:
    def is_actor_up(self):
        """Return true if the LACP actor state is UP"""
        return self.dyn_lacp_actor_state == LACP_ACTOR_UP

    def is_actor_nosync(self):
        """Return true if the LACP actor state is NOSYNC"""
        return self.dyn_lacp_actor_state == LACP_ACTOR_NOSYNC

    def is_actor_init(self):
        """Return true if the LACP actor state is INIT"""
        return self.dyn_lacp_actor_state == LACP_ACTOR_INIT

    def is_actor_none(self):
        """Return true if the LACP actor state is NONE"""
        return self.dyn_lacp_actor_state == LACP_ACTOR_NONE

    def actor_state(self):
        """Return the current LACP actor state"""
        return self.dyn_lacp_actor_state

    def actor_notconfigured(self):
        """Set the LACP actor state to NOTCONFIGURED"""
        self.dyn_lacp_actor_state = LACP_ACTOR_NOTCONFIGURED

    def actor_none(self):
        """Set the LACP actor state to NONE"""
        self.dyn_lacp_actor_state = LACP_ACTOR_NONE

    def actor_init(self):
        """Set the LACP actor state to INIT"""
        self.dyn_lacp_actor_state = LACP_ACTOR_INIT

    def actor_up(self):
        """Set the LACP actor state to UP"""
        self.dyn_lacp_actor_state = LACP_ACTOR_UP

    def actor_nosync(self):
        """Set the LACP actor state to NOSYNC"""
        self.dyn_lacp_actor_state = LACP_ACTOR_NOSYNC

    def actor_state_name(self, state):
        """Return the string of the actor state"""
        return LACP_ACTOR_DISPLAY_DICT[state]

    # LACP PORT ROLES:
    def is_port_selected(self):
        """Return true if the lacp is a SELECTED port"""
        return self.dyn_lacp_port_selected == LACP_PORT_SELECTED

    def is_port_unselected(self):
        """Return true if the lacp is an UNSELECTED port"""
        return self.dyn_lacp_port_selected == LACP_PORT_UNSELECTED

    def is_port_standby(self):
        """Return true if the lacp is a port in STANDBY"""
        return self.dyn_lacp_port_selected == LACP_PORT_STANDBY

    def lacp_port_state(self):
        """Return the current LACP port state"""
        return self.dyn_lacp_port_selected

    def select_port(self):
        """SELECT the current LACP port"""
        self.dyn_lacp_port_selected = LACP_PORT_SELECTED

    def deselect_port(self):
        """UNSELECT the current LACP port"""
        self.dyn_lacp_port_selected = LACP_PORT_UNSELECTED

    def standby_port(self):
        """Set LACP port state to STANDBY"""
        self.dyn_lacp_port_selected = LACP_PORT_STANDBY

    def deconfigure_port(self):
        """Set LACP port state to NOTCONFIGURED"""
        self.dyn_lacp_port_selected = LACP_PORT_NOTCONFIGURED

    def port_role_name(self, state):
        """Return the LACP port role state name"""
        return LACP_PORT_DISPLAY_DICT[state]

    # STACK PORT ROLES:
    def is_stack_admin_down(self):
        """Return True if port is in ADMIN_DOWN state."""
        return self.dyn_stack_current_state == STACK_STATE_ADMIN_DOWN

    def is_stack_none(self):
        """Return True if port is in NONE state."""
        return self.dyn_stack_current_state == STACK_STATE_NONE

    def is_stack_init(self):
        """Return True if port is in INIT state."""
        return self.dyn_stack_current_state == STACK_STATE_INIT

    def is_stack_bad(self):
        """Return True if port is in BAD state."""
        return self.dyn_stack_current_state == STACK_STATE_BAD

    def is_stack_up(self):
        """Return True if port is in UP state."""
        return self.dyn_stack_current_state == STACK_STATE_UP

    def is_stack_gone(self):
        """Return True if port is in GONE state."""
        return self.dyn_stack_current_state == STACK_STATE_GONE

    def stack_admin_down(self):
        """Change the current stack state to ADMIN_DOWN."""
        self.dyn_stack_current_state = STACK_STATE_ADMIN_DOWN

    def stack_init(self):
        """Change the current stack state to INIT_DOWN."""
        self.dyn_stack_current_state = STACK_STATE_INIT

    def stack_bad(self):
        """Change the current stack state to BAD."""
        self.dyn_stack_current_state = STACK_STATE_BAD

    def stack_up(self):
        """Change the current stack state to UP."""
        self.dyn_stack_current_state = STACK_STATE_UP

    def stack_gone(self):
        """Change the current stack state to GONE."""
        self.dyn_stack_current_state = STACK_STATE_GONE
