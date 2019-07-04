"""Configuration for ACLs."""

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
import copy
import netaddr

from faucet import valve_of
from faucet import valve_acl
from faucet.valve_of import MATCH_FIELDS, OLD_MATCH_FIELDS
from faucet.conf import Conf, test_config_condition, InvalidConfigError
from faucet.valve_table import wildcard_table


class ACL(Conf):
    """Contains the state for an ACL, including the configuration.

ACL Config

ACLs are configured under the 'acls' configuration block. The acls block
contains a dictionary of individual acls each keyed by its name.

Each acl contains a list of rules, a packet will have the first matching rule
applied to it.

Each rule is a dictionary containing the single key 'rule' with the value the
matches and actions for the rule.

The matches are key/values based on the ryu RESTFul API.
The key 'actions' contains a dictionary with keys/values as follows:

 * allow (int): if 1 allow the packet to continue through the Faucet \
       pipeline, if 0 drop the packet.
 * force_port_vlan (int): if 1, do not verify the VLAN/port association \
       for this packet and override any VLAN ACL on the forced VLAN.
 * meter (str): meter to apply to the packet
 * output (dict): used to output a packet directly. details below.
 * cookie (int): set flow cookie to this value on this flow

The output action contains a dictionary with the following elements:

 * tunnel (dict): the tunnel formation, creates a tunnel from the applied port(s) \
       to the specified destination
 * port (int or string): the port to output the packet to
 * ports (list): a list of the ports (int or string) to output the packet to
 * set_fields (list): a list of fields to set with values
 * pop_vlans: (int): pop the packet vlan before outputting
 * vlan_vid: (int): push the vlan vid on the packet when outputting
 * vlan_vids: (list): push the list of vlans on the packet when outputting, with option eth_type
 * swap_vid (int): rewrite the vlan vid of the packet when outputting
 * failover (dict): Output with a failover port (experimental)
"""

    defaults = {
        'rules': None,
        'exact_match': False,
        'dot1x_assigned': False,
    }
    defaults_types = {
        'rules': list,
        'exact_match': bool,
        'dot1x_assigned': bool,
    }
    rule_types = {
        'cookie': int,
        'actions': dict,
        'description': str,
    }
    actions_types = {
        'meter': str,
        'mirror': (str, int),
        'output': dict,
        'allow': int,
        'force_port_vlan': int,
    }
    output_actions_types = {
        'tunnel': dict,
        'port': (str, int),
        'ports': list,
        'failover': dict,
        'set_fields': list,
        'pop_vlans': int,
        'swap_vid': int,
        'vlan_vid': int,
        'vlan_vids': list,
    }
    tunnel_types = {
        'type': str,
        'tunnel_id': (str, int),
        'dp': str,
        'port': (str, int),
    }

    def __init__(self, _id, dp_id, conf):
        self.rules = []
        self.exact_match = None
        self.dot1x_assigned = None
        self.meter = False
        self.matches = {}
        self.set_fields = set()

        #TODO: Would be possible to save the names instead of the DP and port objects
        # TUNNEL:
        #   src_port: PORT object / port number
        #       source port
        #   src_dp: DP object
        #       source dp
        #   dst_port: PORT object / port number
        #       final destination port
        #   dst_dp: DP object
        #       final destination dp
        #   tunnel_id: int
        #       ID to represent the tunnel
        #   tunnel_type: str ('vlan')
        #       tunnel type specification
        self.tunnel_info = {}

        for match_fields in (MATCH_FIELDS, OLD_MATCH_FIELDS):
            self.rule_types.update({match: (str, int) for match in match_fields})
        conf = copy.deepcopy(conf)
        if isinstance(conf, dict):
            rules = conf.get('rules', [])
        elif isinstance(conf, list):
            rules = conf
            conf = {}
        else:
            raise InvalidConfigError(
                'ACL conf is an invalid type %s' % _id)
        conf['rules'] = []
        for rule in rules:
            normalized_rule = rule
            if isinstance(rule, dict):
                normalized_rule = rule.get('rule', rule)
                if normalized_rule is None:
                    normalized_rule = {k: v for k, v in rule.items() if v is not None}
            test_config_condition(not isinstance(normalized_rule, dict), (
                'ACL rule is %s not %s (%s)' % (type(normalized_rule), dict, rules)))
            conf['rules'].append(normalized_rule)
        super(ACL, self).__init__(_id, dp_id, conf)

    def check_config(self):
        test_config_condition(
            not self.rules, 'no rules found for ACL %s' % self._id)
        for rule in self.rules:
            self._check_conf_types(rule, self.rule_types)
            for rule_field, rule_conf in rule.items():
                if rule_field == 'cookie':
                    test_config_condition(
                        rule_conf < 0 or rule_conf > 2**16,
                        'rule cookie value must be 0-2**16')
                elif rule_field == 'actions':
                    test_config_condition(
                        not rule_conf,
                        'Missing rule actions in ACL %s' % self._id)
                    self._check_conf_types(rule_conf, self.actions_types)
                    for action_name, action_conf in rule_conf.items():
                        if action_name == 'output':
                            self._check_conf_types(
                                action_conf, self.output_actions_types)

    def build(self, meters, vid, port_num):
        """Check that ACL can be built from config."""

        class NullRyuDatapath:
            """Placeholder Ryu Datapath."""
            ofproto = valve_of.ofp

        self.matches = {}
        self.set_fields = set()
        self.meter = False
        if self.rules:
            try:
                ofmsgs = valve_acl.build_acl_ofmsgs(
                    [self], wildcard_table,
                    [valve_of.goto_table(wildcard_table)],
                    [valve_of.goto_table(wildcard_table)],
                    2**16-1, meters, self.exact_match,
                    vlan_vid=vid, port_num=port_num)
            except (netaddr.core.AddrFormatError, KeyError, ValueError) as err:
                raise InvalidConfigError(err)
            test_config_condition(not ofmsgs, 'OF messages is empty')
            for ofmsg in ofmsgs:
                ofmsg.datapath = NullRyuDatapath()
                ofmsg.set_xid(0)
                try:
                    ofmsg.serialize()
                except (KeyError, ValueError) as err:
                    raise InvalidConfigError(err)
                except Exception as err:
                    print(ofmsg)
                    raise err
                if valve_of.is_flowmod(ofmsg):
                    apply_actions = []
                    for inst in ofmsg.instructions:
                        if valve_of.is_apply_actions(inst):
                            apply_actions.extend(inst.actions)
                        elif valve_of.is_meter(inst):
                            self.meter = True
                    for action in apply_actions:
                        if valve_of.is_set_field(action):
                            self.set_fields.add(action.key)
                    for match, value in ofmsg.match.items():
                        has_mask = isinstance(value, (tuple, list))
                        if has_mask or match not in self.matches:
                            self.matches[match] = has_mask
        return (self.matches, self.set_fields, self.meter)

    def get_meters(self):
        for rule in self.rules:
            if 'actions' not in rule or 'meter' not in rule['actions']:
                continue
            yield rule['actions']['meter']

    def get_mirror_destinations(self):
        for rule in self.rules:
            if 'actions' not in rule or 'mirror' not in rule['actions']:
                continue
            yield rule['actions']['mirror']

    def get_in_port_match(self, tunnel_id):
        """
        Returns a port number of the src_port of the tunnel that the ingress tunnel ACL \
            will need to match to.
        Args:
            tunnel_id (int): tunnel identifier to obtain the src_port
        Returns:
            int OR None: src_port number if it exists, None otherwise
        """
        return self.tunnel_info[tunnel_id]['src_port']

    def get_tunnel_id(self, rule_index):
        """
        Gets the tunnel ID for the rule
        Args:
            rule_index (int): Index of the tunnel rule in the self.rules list
        Returns:
            tunnel_id (int): Identifier for the tunnel
        """
        tunnel_conf = self.rules[rule_index]
        return tunnel_conf['actions']['output']['tunnel']

    def unpack_tunnel(self, tunnel_id):
        """
        Retrieves the information from the tunnel dict for the tunnel with id
        Args:
            tunnel_id (int): Identifier for the tunnel
        Returns:
            (src_dp, src_port, dst_dp, dst_port): Tunnel information
        """
        src_dp = self.tunnel_info[tunnel_id]['src_dp']
        src_port = self.tunnel_info[tunnel_id]['src_port']
        dst_dp = self.tunnel_info[tunnel_id]['dst_dp']
        dst_port = self.tunnel_info[tunnel_id]['dst_port']
        return (src_dp, src_port, dst_dp, dst_port)

    def get_tunnel_rule_indices(self):
        """
        Get the rules from the rule conf that contain tunnel outputs
        Returns:
            rules (list): list of integer indices into the self.rules rule list that \
                contain tunnel information
        """
        rules = []
        for i, rule_conf in enumerate(self.rules):
            if 'actions' in rule_conf:
                if 'output' in rule_conf['actions']:
                    if 'tunnel' in rule_conf['actions']['output']:
                        rules.append(i)
        return rules

    def remove_non_tunnel_rules(self):
        """
        Removes all non-tunnel rules from the ACL \
            and removes all match fields and non-tunnel required actions from the tunnel rules
        """
        new_rules = []
        tunnel_indices = self.get_tunnel_rule_indices()
        for tunnel_index in tunnel_indices:
            tunnel_id = self.get_tunnel_id(tunnel_index)
            new_rule = {'actions': {'output': {'tunnel': tunnel_id}}}
            new_rules.append(new_rule)
        self.rules = new_rules

    def verify_tunnel_rules(self, dp):
        """
        Verify the actions in the tunnel ACL to by making sure the user hasn't specified an \
            action/match that will create a clash.
        Args:
            dp (DP): The dp that this tunnel acl object belongs to
        TODO: Choose what combinations of matches & actions to disallow with a tunnel
        """
        for tunnel_index in self.get_tunnel_rule_indices():
            tunnel_id = self.get_tunnel_id(tunnel_index)
            src_dp, _, _, _ = self.unpack_tunnel(tunnel_id)
            if dp == src_dp:
                self.matches['in_port'] = False
                self.set_fields.add('vlan_vid')
            else:
                self.matches['vlan_vid'] = False
                self.remove_non_tunnel_rules()

    def update_tunnel_acl_conf(self, dp):
        """
        Update the ACL rule conf if the DP is in the path
        Args:
            dp (DP): The dp that this tunnel acl object belongs to
        Returns:
            bool: True if any value was updated
        """
        updated = False
        for tunnel_index in self.get_tunnel_rule_indices():
            tunnel_id = self.get_tunnel_id(tunnel_index)
            src_dp, _, dst_dp, dst_port = self.unpack_tunnel(tunnel_id)
            tunnel_rule = self.rules[tunnel_index]
            if dp.is_in_path(src_dp, dst_dp):
                output_rule = tunnel_rule['actions']['output']
                orig_output_rule = copy.deepcopy(output_rule)
                if dp == dst_dp:
                    if src_dp != dst_dp:
                        if not 'pop_vlans' in output_rule:
                            output_rule['pop_vlans'] = 1
                    if not 'port' in output_rule:
                        output_rule['port'] = dst_port
                else:
                    output_port = dp.shortest_path_port(dst_dp.name)
                    if output_port is None:
                        continue
                    port_number = output_port.number
                    if 'port' not in output_rule:
                        output_rule['port'] = port_number
                    elif port_number != output_rule['port']:
                        output_rule['port'] = port_number
                    if dp == src_dp:
                        output_rule['vlan_vid'] = tunnel_id
                if output_rule != orig_output_rule:
                    updated = True
        return updated

    def _resolve_output_ports(self, action_conf, resolve_port_cb, resolve_tunnel_objects):
        result = {}
        for output_action, output_action_values in action_conf.items():
            if output_action == 'tunnel':
                tunnel = output_action_values
                self._check_conf_types(tunnel, self.tunnel_types)
                src_dp, src_port, dst_dp, dst_port, tunnel_id = resolve_tunnel_objects(
                    tunnel['dp'], tunnel['port'], tunnel['tunnel_id'])
                tunnel_dict = {
                    'src_dp': src_dp,
                    'src_port': src_port,
                    'dst_dp': dst_dp,
                    'dst_port': dst_port,
                    'tunnel_id': tunnel_id,
                    'type': tunnel['type'],
                }
                self.tunnel_info[tunnel_id] = tunnel_dict
                result[output_action] = tunnel_id
            elif output_action == 'port':
                port_name = output_action_values
                port = resolve_port_cb(port_name)
                test_config_condition(
                    not port,
                    ('ACL (%s) output port undefined in DP: %s'\
                    % (self._id, self.dp_id))
                    )
                result[output_action] = port
            elif output_action == 'ports':
                resolved_ports = [
                    resolve_port_cb(p) for p in output_action_values]
                test_config_condition(
                    None in resolved_ports,
                    ('ACL (%s) output port(s) not defined in DP: %s'\
                    % (self._id, self.dp_id))
                    )
                result[output_action] = resolved_ports
            elif output_action == 'failover':
                failover = output_action_values
                test_config_condition(not isinstance(failover, dict), (
                    'failover is not a dictionary'))
                result[output_action] = {}
                for failover_name, failover_values in failover.items():
                    if failover_name == 'ports':
                        resolved_ports = [
                            resolve_port_cb(p) for p in failover_values]
                        test_config_condition(
                            None in resolved_ports,
                            ('ACL (%s) failover port(s) not defined in DP: %s'\
                            % (self._id, self.dp_id))
                            )
                        result[output_action][failover_name] = resolved_ports
                    else:
                        result[output_action][failover_name] = failover_values
            else:
                result[output_action] = output_action_values
        return result

    def resolve_ports(self, resolve_port_cb, resolve_tunnel_objects):
        for rule_conf in self.rules:
            if 'actions' in rule_conf:
                actions_conf = rule_conf['actions']
                resolved_actions = {}
                test_config_condition(not isinstance(actions_conf, dict), (
                    'actions value is not a dictionary'))
                for action_name, action_conf in actions_conf.items():
                    if action_name == 'mirror':
                        resolved_port = resolve_port_cb(action_conf)
                        test_config_condition(
                            resolved_port is None,
                            ('ACL (%s) mirror port is not defined in DP: %s'\
                            % (self._id, self.dp_id))
                            )
                        resolved_actions[action_name] = resolved_port
                    elif action_name == 'output':
                        resolved_action = self._resolve_output_ports(
                            action_conf, resolve_port_cb, resolve_tunnel_objects)
                        resolved_actions[action_name] = resolved_action
                    else:
                        resolved_actions[action_name] = action_conf
                rule_conf['actions'] = resolved_actions


# NOTE: 802.1x steals the port ACL table.
PORT_ACL_8021X = ACL(
    'port_acl_8021x', 0,
    {'rules': [{'eth_type': 1, 'eth_src': '01:02:03:04:05:06', 'actions': {
        'output': {'set_fields': [
            {'eth_src': '01:02:03:04:05:06'}, {'eth_dst': '01:02:03:04:05:06'}]}}}]})
PORT_ACL_8021X.build({}, None, 1)

MAB_ACL_8021X = ACL(
    'mab_acl_8021x', 0,
    {'rules': [{'eth_type': valve_of.ether.ETH_TYPE_IP, 'eth_src': '01:02:03:04:05:06',
                'ip_proto': valve_of.inet.IPPROTO_UDP, 'udp_src': 68, 'udp_dst': 67, }]})
MAB_ACL_8021X.build({}, None, 1)
