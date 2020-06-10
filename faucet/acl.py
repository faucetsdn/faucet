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
        'output': (dict, list),
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
        'type': (str, None),
        'tunnel_id': (str, int, None),
        'dp': str,
        'port': (str, int),
    }

    mutable_attrs = frozenset(['tunnel_sources'])

    def __init__(self, _id, dp_id, conf):
        self.rules = []
        self.exact_match = None
        self.dot1x_assigned = None
        self.meter = False
        self.matches = {}
        self.set_fields = set()
        self._ports_resolved = False

        # Tunnel info maintains the tunnel output information for each tunnel rule
        self.tunnel_info = {}
        # Tunnel sources is a list of the sources in the network for this ACL
        self.tunnel_sources = []
        # Tunnel rules is the rules for each tunnel in the ACL for each source
        self.dyn_tunnel_rules = {}

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

    def finalize(self):
        self._ports_resolved = True
        super(ACL, self).finalize()

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
                            if isinstance(action_conf, (list, tuple)):
                                # New ordered format
                                for subconf in action_conf:
                                    # Make sure only one specified action per list element
                                    test_config_condition(
                                        len(subconf) > 1,
                                        'ACL ordered output must have only one action per element')
                                    # Ensure correct action format
                                    self._check_conf_types(subconf, self.output_actions_types)
                            else:
                                # Old format
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
        """Yield meters for each rule in ACL"""
        for rule in self.rules:
            if 'actions' not in rule or 'meter' not in rule['actions']:
                continue
            yield rule['actions']['meter']

    def get_mirror_destinations(self):
        """Yield mirror destinations for each rule in ACL"""
        for rule in self.rules:
            if 'actions' not in rule or 'mirror' not in rule['actions']:
                continue
            yield rule['actions']['mirror']

    def _resolve_ordered_output_ports(self, output_list, resolve_port_cb, resolve_tunnel_objects):
        """Resolve output actions in the ordered list format"""
        result = []
        for action in output_list:
            for key, value in action.items():
                if key == 'tunnel':
                    tunnel = value
                    # Fetch tunnel items from the tunnel output dict
                    test_config_condition(
                        'dp' not in tunnel,
                        'ACL (%s) tunnel DP not defined' % self._id)
                    tunnel_dp = tunnel['dp']
                    test_config_condition(
                        'port' not in tunnel,
                        'ACL (%s) tunnel port not defined' % self._id)
                    tunnel_port = tunnel['port']
                    tunnel_id = tunnel.get('tunnel_id', None)
                    tunnel_type = tunnel.get('type', 'vlan')
                    # Resolve the tunnel items
                    dst_dp, dst_port, tunnel_id = resolve_tunnel_objects(
                        tunnel_dp, tunnel_port, tunnel_id)
                    # Compile the tunnel into an easy-access dictionary
                    tunnel_dict = {
                        'dst_dp': dst_dp,
                        'dst_port': dst_port,
                        'tunnel_id': tunnel_id,
                        'type': tunnel_type
                    }
                    self.tunnel_info[tunnel_id] = tunnel_dict
                    result.append({key: tunnel_id})
                elif key == 'port':
                    port_name = value
                    port = resolve_port_cb(port_name)
                    test_config_condition(
                        not port,
                        'ACL (%s) output port undefined in DP: %s' % (self._id, self.dp_id))
                    result.append({key: port})
                elif key == 'ports':
                    resolved_ports = [
                        resolve_port_cb(p) for p in value]
                    test_config_condition(
                        None in resolved_ports,
                        'ACL (%s) output port(s) not defined in DP: %s' % (self._id, self.dp_id))
                    result.append({key: resolved_ports})
                elif key == 'failover':
                    failover = value
                    test_config_condition(not isinstance(failover, dict), (
                        'failover is not a dictionary'))
                    failover_dict = {}
                    for failover_name, failover_values in failover.items():
                        if failover_name == 'ports':
                            resolved_ports = [
                                resolve_port_cb(p) for p in failover_values]
                            test_config_condition(
                                None in resolved_ports,
                                'ACL (%s) failover port(s) not defined in DP: %s' % (
                                    self._id, self.dp_id))
                            failover_dict[failover_name] = resolved_ports
                        else:
                            failover_dict[failover_name] = failover_values
                    result.append({key: failover_dict})
                else:
                    result.append(action)
        return result

    def _resolve_output_ports(self, action_conf, resolve_port_cb, resolve_tunnel_objects):
        """Resolve the values for output actions in the ACL"""
        if isinstance(action_conf, (list, tuple)):
            return self._resolve_ordered_output_ports(
                action_conf, resolve_port_cb, resolve_tunnel_objects)
        result = {}
        test_config_condition(
            'vlan_vid' in action_conf and 'vlan_vids' in action_conf,
            'ACL %s has both vlan_vid and vlan_vids defined' % self._id)
        test_config_condition(
            'port' in action_conf and 'ports' in action_conf,
            'ACL %s has both port and ports defined' % self._id)
        for output_action, output_action_values in action_conf.items():
            if output_action == 'tunnel':
                tunnel = output_action_values
                # Fetch tunnel items from the tunnel output dict
                test_config_condition(
                    'dp' not in tunnel,
                    'ACL (%s) tunnel DP not defined' % self._id)
                tunnel_dp = tunnel['dp']
                test_config_condition(
                    'port' not in tunnel,
                    'ACL (%s) tunnel port not defined' % self._id)
                tunnel_port = tunnel['port']
                tunnel_id = tunnel.get('tunnel_id', None)
                tunnel_type = tunnel.get('type', 'vlan')
                # Resolve the tunnel items
                dst_dp, dst_port, tunnel_id = resolve_tunnel_objects(
                    tunnel_dp, tunnel_port, tunnel_id)
                # Compile the tunnel into an easy-access dictionary
                tunnel_dict = {
                    'dst_dp': dst_dp,
                    'dst_port': dst_port,
                    'tunnel_id': tunnel_id,
                    'type': tunnel_type
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
        """Resolve the values for the actions of an ACL"""
        if self._ports_resolved:
            return
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
        self._ports_resolved = True

    def get_num_tunnels(self):
        """Returns the number of tunnels specified in the ACL"""
        num_tunnels = 0
        for rule_conf in self.rules:
            if self.does_rule_contain_tunnel(rule_conf):
                output_conf = rule_conf['actions']['output']
                if isinstance(output_conf, list):
                    for action in output_conf:
                        for key in action:
                            if key == 'tunnel':
                                num_tunnels += 1
                else:
                    if 'tunnel' in output_conf:
                        num_tunnels += 1
        return num_tunnels

    def get_tunnel_rules(self, tunnel_id):
        """Return the list of rules that apply a specific tunnel ID"""
        rules = []
        for rule_conf in self.rules:
            if self.does_rule_contain_tunnel(rule_conf):
                output_conf = rule_conf['actions']['output']
                if isinstance(output_conf, (list, tuple)):
                    for action in output_conf:
                        for key, value in action.items():
                            if key == 'tunnel' and value == tunnel_id:
                                rules.append(rule_conf)
                                continue
                else:
                    if output_conf['tunnel'] == tunnel_id:
                        rules.append(rule_conf)
        return rules

    def does_rule_contain_tunnel(self, rule_conf):
        """Return true if the ACL rule contains a tunnel"""
        if 'actions' in rule_conf:
            if 'output' in rule_conf['actions']:
                output_conf = rule_conf['actions']['output']
                if isinstance(output_conf, (list, tuple)):
                    for action in output_conf:
                        for key in action:
                            if key == 'tunnel':
                                return True
                else:
                    if 'tunnel' in output_conf:
                        return True
        return False

    def is_tunnel_acl(self):
        """Return true if the ACL contains a tunnel"""
        if self.tunnel_info:
            return True
        for rule_conf in self.rules:
            if self.does_rule_contain_tunnel(rule_conf):
                return True
        return False

    def add_tunnel_source(self, dp, port):
        """Add a source dp/port pair for the tunnel ACL"""
        self.tunnel_sources += ({'dp': dp, 'port': port},)
        for _id in self.tunnel_info:
            self.dyn_tunnel_rules.setdefault(_id, [])
            self.dyn_tunnel_rules[_id].append([])

    def verify_tunnel_rules(self):
        """Make sure that matches & set fields are configured correctly to handle tunnels"""
        if 'in_port' not in self.matches:
            self.matches['in_port'] = False
        if 'vlan_vid' not in self.matches:
            self.matches['vlan_vid'] = False
        if 'vlan_vid' not in self.set_fields:
            self.set_fields.add('vlan_vid')

    def update_source_tunnel_rules(self, curr_dp, source_id, tunnel_id, out_port):
        """Update the tunnel rulelist for when the output port has changed"""
        src_dp = self.tunnel_sources[source_id]['dp']
        dst_dp = self.tunnel_info[tunnel_id]['dst_dp']
        prev_list = self.dyn_tunnel_rules[tunnel_id][source_id]
        new_list = []
        if curr_dp == src_dp and curr_dp != dst_dp:
            # SRC DP: in_port, actions=[push_vlan, output, pop_vlans]
            new_list.append({'vlan_vid': tunnel_id})
            new_list.append({'port': out_port})
            new_list.append({'pop_vlans': 1})
        elif curr_dp == dst_dp and curr_dp != src_dp:
            # DST DP: in_port, vlan_vid, actions=[pop_vlan, output]
            new_list.append({'pop_vlans': 1})
            new_list.append({'port': out_port})
        else:
            # SINGLE DP: in_port, actions=[out_port]
            # TRANSIT DP: in_port, vlan_vid, actions=[output]
            new_list.append({'port': out_port})
        if new_list != prev_list:
            self.dyn_tunnel_rules[tunnel_id][source_id] = new_list
            return True
        return True


# NOTE: 802.1x steals the port ACL table.
PORT_ACL_8021X = ACL(
    'port_acl_8021x', 0,
    {'rules': [
        {'eth_type': 1, 'eth_src': '01:02:03:04:05:06', 'actions': {'output': {
            'port': valve_of.ofp.OFPP_LOCAL, 'set_fields': [
                {'eth_src': '01:02:03:04:05:06'}, {'eth_dst': '01:02:03:04:05:06'}]}}}]})
PORT_ACL_8021X.build({}, None, 1)

MAB_ACL_8021X = ACL(
    'mab_acl_8021x', 0,
    {'rules': [{
        'eth_type': valve_of.ether.ETH_TYPE_IP, 'eth_src': '01:02:03:04:05:06',
        'ip_proto': valve_of.inet.IPPROTO_UDP, 'udp_src': 68, 'udp_dst': 67,
        'actions': {'output': {'port': valve_of.ofp.OFPP_LOCAL}}}]})
MAB_ACL_8021X.build({}, None, 1)
