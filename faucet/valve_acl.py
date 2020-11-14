"""Compose ACLs on ports."""

# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
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
# distributed under the License is distributed on an "AS IS" BASIS
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from faucet import valve_of
from faucet import valve_packet
from faucet.valve_manager_base import ValveManagerBase
from faucet.conf import InvalidConfigError


def push_vlan(acl_table, vlan_vid):
    """Push a VLAN tag with optional selection of eth type."""
    vid = vlan_vid
    vlan_eth_type = None
    if isinstance(vlan_vid, dict):
        vid = vlan_vid['vid']
        if 'eth_type' in vlan_vid:
            vlan_eth_type = vlan_vid['eth_type']
    if vlan_eth_type is None:
        return valve_of.push_vlan_act(acl_table, vid)
    return valve_of.push_vlan_act(
        acl_table, vid, eth_type=vlan_eth_type)


def build_ordered_output_actions(acl_table, output_list, tunnel_rules=None, source_id=None):
    """Build actions from ordered ACL output list"""
    output_actions = []
    output_ports = []
    output_ofmsgs = []
    for action in output_list:
        for key, value in action.items():
            if key == 'pop_vlans':
                for _ in range(value):
                    output_actions.append(valve_of.pop_vlan())
            if key == 'vlan_vid':
                output_actions.extend(push_vlan(acl_table, value))
            if key == 'swap_vid':
                output_actions.append(acl_table.set_vlan_vid(value))
            if key == 'vlan_vids':
                for vlan_vid in value:
                    output_actions.extend(push_vlan(acl_table, vlan_vid))
            if key == 'set_fields':
                for set_field in value:
                    output_actions.append(acl_table.set_field(**set_field))
            if key == 'port':
                output_ports.append(value)
                output_actions.append(valve_of.output_port(value))
            if key == 'ports':
                for output_port in value:
                    output_ports.append(output_port)
                    output_actions.append(valve_of.output_port(output_port))
            if key == 'failover':
                group_id = value['group_id']
                buckets = []
                for port in value['ports']:
                    buckets.append(valve_of.bucket(
                        watch_port=port, actions=[valve_of.output_port(port)]))
                output_ofmsgs.append(valve_of.groupdel(group_id=group_id))
                output_ofmsgs.append(valve_of.groupadd_ff(group_id=group_id, buckets=buckets))
                output_actions.append(valve_of.group_act(group_id=group_id))
            if key == 'tunnel' and tunnel_rules and source_id is not None:
                source_rule = tunnel_rules[value][source_id]
                _, tunnel_actions, tunnel_ofmsgs = build_output_actions(acl_table, source_rule)
                output_actions.extend(tunnel_actions)
                tunnel_ofmsgs.extend(tunnel_ofmsgs)
    return (output_ports, output_actions, output_ofmsgs)


def rewrite_vlan(acl_table, output_dict):
    """Implement actions to rewrite VLAN headers."""
    vlan_actions = []
    if 'pop_vlans' in output_dict:
        for _ in range(output_dict['pop_vlans']):
            vlan_actions.append(valve_of.pop_vlan())
    # if vlan tag is specified, push it.
    if 'vlan_vid' in output_dict:
        vlan_actions.extend(push_vlan(acl_table, output_dict['vlan_vid']))
    # swap existing VID
    elif 'swap_vid' in output_dict:
        vlan_actions.append(
            acl_table.set_vlan_vid(output_dict['swap_vid']))
    # or, if a list, push them all (all with type Q).
    elif 'vlan_vids' in output_dict:
        for vlan_vid in output_dict['vlan_vids']:
            vlan_actions.extend(push_vlan(acl_table, vlan_vid))
    return vlan_actions


def build_output_actions(acl_table, output_dict, tunnel_rules=None, source_id=None):
    """Implement actions to alter packet/output."""
    if isinstance(output_dict, (list, tuple)):
        return build_ordered_output_actions(acl_table, output_dict, tunnel_rules, source_id)
    output_actions = []
    output_port = None
    ofmsgs = []
    # rewrite any VLAN headers first always
    vlan_actions = rewrite_vlan(acl_table, output_dict)
    if vlan_actions:
        output_actions.extend(vlan_actions)
    if 'set_fields' in output_dict:
        for set_field in output_dict['set_fields']:
            output_actions.append(acl_table.set_field(**set_field))
    if 'port' in output_dict:
        output_port = output_dict['port']
        output_actions.append(valve_of.output_port(output_port))
    if 'ports' in output_dict:
        for output_port in output_dict['ports']:
            output_actions.append(valve_of.output_port(output_port))
    if 'failover' in output_dict:
        failover = output_dict['failover']
        group_id = failover['group_id']
        buckets = []
        for port in failover['ports']:
            buckets.append(valve_of.bucket(
                watch_port=port, actions=[valve_of.output_port(port)]))
        ofmsgs.append(valve_of.groupdel(group_id=group_id))
        ofmsgs.append(valve_of.groupadd_ff(group_id=group_id, buckets=buckets))
        output_actions.append(valve_of.group_act(group_id=group_id))
    if 'tunnel' in output_dict and tunnel_rules and source_id is not None:
        tunnel_id = output_dict['tunnel']
        source_rule = tunnel_rules[tunnel_id][source_id]
        _, tunnel_actions, tunnel_ofmsgs = build_output_actions(acl_table, source_rule)
        output_actions.extend(tunnel_actions)
        tunnel_ofmsgs.extend(tunnel_ofmsgs)
    return (output_port, output_actions, ofmsgs)


# possibly replace with a class for ACLs
def build_acl_entry(  # pylint: disable=too-many-arguments,too-many-branches,too-many-statements
        acl_table, rule_conf, meters,
        acl_allow_inst, acl_force_port_vlan_inst,
        port_num=None, vlan_vid=None, tunnel_rules=None, source_id=None):
    """Build flow/groupmods for one ACL rule entry."""
    acl_inst = []
    acl_act = []
    acl_match_dict = {}
    acl_ofmsgs = []
    acl_cookie = None
    allow_inst = acl_allow_inst

    for attrib, attrib_value in rule_conf.items():
        if attrib == 'in_port':
            continue
        if attrib == 'cookie':
            acl_cookie = attrib_value
            continue
        if attrib == 'description':
            continue
        if attrib == 'actions':
            allow = False
            allow_specified = False
            if 'allow' in attrib_value:
                allow_specified = True
                if attrib_value['allow'] == 1:
                    allow = True
            if 'force_port_vlan' in attrib_value:
                if attrib_value['force_port_vlan'] == 1:
                    allow_inst = acl_force_port_vlan_inst
            if 'meter' in attrib_value:
                meter_name = attrib_value['meter']
                acl_inst.append(valve_of.apply_meter(meters[meter_name].meter_id))
            if 'mirror' in attrib_value:
                port_no = attrib_value['mirror']
                acl_act.append(valve_of.output_port(port_no))
                if not allow_specified:
                    allow = True
            if 'output' in attrib_value:
                output_port, output_actions, output_ofmsgs = build_output_actions(
                    acl_table, attrib_value['output'], tunnel_rules, source_id)
                acl_act.extend(output_actions)
                acl_ofmsgs.extend(output_ofmsgs)

                # if port specified, output packet now and exit pipeline.
                if not allow and output_port is not None:
                    continue

            if allow:
                acl_inst.extend(allow_inst)
        else:
            acl_match_dict[attrib] = attrib_value
    if port_num is not None:
        acl_match_dict['in_port'] = port_num
    if vlan_vid is not None:
        acl_match_dict['vlan_vid'] = valve_of.vid_present(vlan_vid)
    try:
        acl_match = valve_of.match_from_dict(acl_match_dict)
    except TypeError:
        raise InvalidConfigError('invalid type in ACL')
    if acl_act:
        acl_inst.append(valve_of.apply_actions(acl_act))
    return (acl_match, acl_inst, acl_cookie, acl_ofmsgs)


def build_tunnel_ofmsgs(rule_conf, acl_table, priority,
                        port_num=None, vlan_vid=None, flowdel=False):
    """Build a specific tunnel only ofmsgs"""
    ofmsgs = []
    acl_inst = []
    acl_match = []
    acl_match_dict = {}
    _, output_actions, output_ofmsgs = build_output_actions(acl_table, rule_conf)
    ofmsgs.extend(output_ofmsgs)
    acl_inst.append(valve_of.apply_actions(output_actions))
    if port_num is not None:
        acl_match_dict['in_port'] = port_num
    if vlan_vid is not None:
        acl_match_dict['vlan_vid'] = valve_of.vid_present(vlan_vid)
    acl_match = valve_of.match_from_dict(acl_match_dict)
    flowmod = acl_table.flowmod(acl_match, priority=priority, inst=tuple(acl_inst))
    if flowdel:
        ofmsgs.append(acl_table.flowdel(match=acl_match, priority=priority, strict=False))
    ofmsgs.append(flowmod)
    return ofmsgs


def build_rule_ofmsgs(rule_conf, acl_table,
                      acl_allow_inst, acl_force_port_vlan_inst,
                      highest_priority, acl_rule_priority, meters,
                      exact_match, port_num=None, vlan_vid=None,
                      tunnel_rules=None, source_id=None, flowdel=False):
    """Build an ACL rule and return OFMSGs"""
    ofmsgs = []
    acl_match, acl_inst, acl_cookie, acl_ofmsgs = build_acl_entry(
        acl_table, rule_conf, meters,
        acl_allow_inst, acl_force_port_vlan_inst,
        port_num, vlan_vid, tunnel_rules, source_id)
    ofmsgs.extend(acl_ofmsgs)
    priority = acl_rule_priority
    if exact_match:
        priority = highest_priority
    flowmod = acl_table.flowmod(
        acl_match, priority=priority, inst=tuple(acl_inst), cookie=acl_cookie)
    if flowdel:
        ofmsgs.append(acl_table.flowdel(match=acl_match, priority=priority))
    ofmsgs.append(flowmod)
    return ofmsgs


def build_acl_ofmsgs(acls, acl_table,
                     acl_allow_inst, acl_force_port_vlan_inst,
                     highest_priority, meters,
                     exact_match, port_num=None, vlan_vid=None):
    """Build flow/groupmods for all entries in an ACL."""
    ofmsgs = []
    acl_rule_priority = highest_priority
    for acl in acls:
        for rule_conf in acl.rules:
            ofmsgs.extend(build_rule_ofmsgs(
                rule_conf, acl_table,
                acl_allow_inst, acl_force_port_vlan_inst,
                highest_priority, acl_rule_priority, meters,
                exact_match, port_num, vlan_vid))
            acl_rule_priority -= 1
    return ofmsgs


def build_acl_port_of_msgs(acl, vid, port_num, acl_table, goto_table, priority):
    """A Helper function for building Openflow Mod Messages for Port ACLs"""
    ofmsgs = None
    if acl.rules:
        ofmsgs = build_acl_ofmsgs(
            [acl], acl_table,
            [valve_of.goto_table(goto_table)],
            [valve_of.goto_table(goto_table)],
            priority, acl.meter, acl.exact_match,
            vlan_vid=vid, port_num=port_num)
    return ofmsgs


def add_mac_address_to_match(match, eth_src):
    """Add or change the value of a match type"""
    # NOTE: This function has been created to work around for
    # OFPMatch.set_dl_src() not storing persistent changes
    if not eth_src:
        return match

    dict_match = dict(match.items())
    dict_match['eth_src'] = eth_src
    return valve_of.match_from_dict(dict_match)


class ValveAclManager(ValveManagerBase):
    """Handle installation of ACLs on a DP"""

    def __init__(self, port_acl_table, vlan_acl_table, egress_acl_table,
                 pipeline, meters, dp_acls=None):
        self.dp_acls = dp_acls
        self.port_acl_table = port_acl_table
        self.vlan_acl_table = vlan_acl_table
        self.egress_acl_table = egress_acl_table
        self.pipeline = pipeline
        self.acl_priority = self._FILTER_PRIORITY
        self.override_priority = self.acl_priority + 1
        self.auth_priority = self._HIGH_PRIORITY
        self.low_priority = self.auth_priority - 1
        self.meters = meters

    def initialise_tables(self):
        """Install dp acls if configured"""
        ofmsgs = []
        if self.dp_acls:
            acl_allow_inst = self.pipeline.accept_to_vlan()
            acl_force_port_vlan_inst = self.pipeline.accept_to_l2_forwarding()
            ofmsgs.extend(build_acl_ofmsgs(
                self.dp_acls, self.port_acl_table, acl_allow_inst,
                acl_force_port_vlan_inst, self.acl_priority, self.meters,
                False))
        return ofmsgs

    def _port_acls_allowed(self, port):
        return not self.dp_acls and not port.output_only and self.port_acl_table

    def add_port(self, port):
        """Install port acls if configured"""
        ofmsgs = []
        if self._port_acls_allowed(port):
            in_port_match = self.port_acl_table.match(in_port=port.number)
            acl_allow_inst = self.pipeline.accept_to_vlan()
            acl_force_port_vlan_inst = self.pipeline.accept_to_l2_forwarding()
            if port.acls_in:
                ofmsgs.extend(build_acl_ofmsgs(
                    port.acls_in, self.port_acl_table,
                    acl_allow_inst, acl_force_port_vlan_inst,
                    self.acl_priority, self.meters,
                    port.acls_in[0].exact_match, port_num=port.number))
            elif not port.dot1x:
                ofmsgs.append(self.port_acl_table.flowmod(
                    in_port_match,
                    priority=self.acl_priority,
                    inst=tuple(acl_allow_inst)))
        return ofmsgs

    def del_port(self, port):
        ofmsgs = []
        if self._port_acls_allowed(port):
            in_port_match = self.port_acl_table.match(in_port=port.number)
            ofmsgs.append(self.port_acl_table.flowdel(in_port_match, self.acl_priority))
        return ofmsgs

    def cold_start_port(self, port):
        """Reload acl for a port by deleting existing rules and calling
        add_port"""
        ofmsgs = []
        ofmsgs.extend(self.del_port(port))
        ofmsgs.extend(self.add_port(port))
        return ofmsgs

    def add_vlan(self, vlan, cold_start):
        """Install vlan ACLS if configured"""
        ofmsgs = []
        if vlan.acls_in:
            acl_allow_inst = self.pipeline.accept_to_classification()
            acl_force_port_vlan_inst = self.pipeline.accept_to_l2_forwarding()
            ofmsgs = build_acl_ofmsgs(
                vlan.acls_in, self.vlan_acl_table, acl_allow_inst,
                acl_force_port_vlan_inst, self.acl_priority, self.meters,
                vlan.acls_in[0].exact_match, vlan_vid=vlan.vid)
        if self.egress_acl_table is not None:
            egress_acl_allow_inst = self.pipeline.accept_to_egress()
            if vlan.acls_out:
                ofmsgs.extend(build_acl_ofmsgs(
                    vlan.acls_out, self.egress_acl_table, egress_acl_allow_inst,
                    egress_acl_allow_inst, self.acl_priority, self.meters,
                    vlan.acls_out[0].exact_match, vlan_vid=vlan.vid
                    ))
            else:
                ofmsgs.append(self.egress_acl_table.flowmod(
                    self.egress_acl_table.match(vlan=vlan),
                    priority=self.acl_priority,
                    inst=tuple(egress_acl_allow_inst),
                    ))
        return ofmsgs

    def add_authed_mac(self, port_num, mac):
        """Add authed mac address"""
        return [self.port_acl_table.flowmod(
            self.port_acl_table.match(in_port=port_num, eth_src=mac),
            priority=self.auth_priority,
            inst=tuple(self.pipeline.accept_to_vlan()))]

    def del_authed_mac(self, port_num, mac=None, strict=True):
        """remove authed mac address"""
        if mac:
            return [self.port_acl_table.flowdel(
                self.port_acl_table.match(in_port=port_num, eth_src=mac),
                priority=self.auth_priority,
                strict=strict)]
        return [self.port_acl_table.flowdel(
            self.port_acl_table.match(in_port=port_num),
            priority=self.auth_priority,
            strict=strict)]

    def del_port_acl(self, acl, port_num, mac=None):
        """Delete ACL rules for Port"""
        def convert_to_flow_del(ofp_flowmods):
            flowdels = []
            for flowmod in ofp_flowmods:
                flowdels.append(self.port_acl_table.flowdel(
                    match=flowmod.match, priority=flowmod.priority))

            return flowdels

        pipeline_vlan_table = self.pipeline.vlan_table
        flowmods = build_acl_port_of_msgs(acl, None, port_num, self.port_acl_table,
                                          pipeline_vlan_table, self.auth_priority)
        for flow in flowmods:
            flow.match = add_mac_address_to_match(flow.match, mac)

        return convert_to_flow_del(flowmods)

    def add_port_acl(self, acl, port_num, mac=None):
        """Create ACL openflow rules for Port"""
        pipeline_vlan_table = self.pipeline.vlan_table
        flowmods = build_acl_port_of_msgs(acl, None, port_num, self.port_acl_table,
                                          pipeline_vlan_table, self.auth_priority)

        for flow in flowmods:
            flow.match = add_mac_address_to_match(flow.match, mac)

        return flowmods

    def create_dot1x_flow_pair(self, port_num, nfv_sw_port_num, mac):
        """Create dot1x flow pair"""
        ofmsgs = [
            self.port_acl_table.flowmod(
                match=self.port_acl_table.match(
                    in_port=port_num,
                    eth_type=valve_packet.ETH_EAPOL),
                priority=self.override_priority,
                inst=(valve_of.apply_actions([
                    self.port_acl_table.set_field(eth_dst=mac),
                    valve_of.output_port(nfv_sw_port_num)]),),
            ),
            self.port_acl_table.flowmod(
                match=self.port_acl_table.match(
                    in_port=nfv_sw_port_num,
                    eth_type=valve_packet.ETH_EAPOL,
                    eth_src=mac),
                priority=self.override_priority,
                inst=(valve_of.apply_actions([
                    self.port_acl_table.set_field(
                        eth_src=valve_packet.EAPOL_ETH_DST),
                    valve_of.output_port(port_num)
                ]),),
            )
        ]

        return ofmsgs

    def del_dot1x_flow_pair(self, port_num, nfv_sw_port_num, mac):
        """Deletes dot1x flow pair"""
        ofmsgs = [
            self.port_acl_table.flowdel(
                match=self.port_acl_table.match(
                    in_port=nfv_sw_port_num,
                    eth_type=valve_packet.ETH_EAPOL,
                    eth_src=mac),
                priority=self.override_priority,
                ),
            self.port_acl_table.flowdel(
                match=self.port_acl_table.match(
                    in_port=port_num,
                    eth_type=valve_packet.ETH_EAPOL),
                priority=self.override_priority,
                )
            ]
        return ofmsgs

    def create_mab_flow(self, port_num, nfv_sw_port_num, mac):
        """
        Create MAB ACL for sending IP Activity to Chewie NFV
            Returns flowmods to send all IP traffic to Chewie

        Args:
            port_num (int): Number of port in
            nfv_sw_port_num(int): Number of port out
            mac(str): MAC address of the valve/port combo

        """
        return self.port_acl_table.flowmod(
            match=self.port_acl_table.match(
                in_port=port_num,
                eth_type=valve_of.ether.ETH_TYPE_IP,
                nw_proto=valve_of.inet.IPPROTO_UDP,
                udp_src=68,
                udp_dst=67,
            ),
            priority=self.low_priority,
            inst=(valve_of.apply_actions([
                self.port_acl_table.set_field(eth_dst=mac),
                valve_of.output_port(nfv_sw_port_num)]),),
        )

    def del_mab_flow(self, port_num, _nfv_sw_port_num, _mac):
        """
        Remove MAB ACL for sending IP Activity to Chewie NFV
            Returns flowmods to send all IP traffic to Chewie

        Args:
            port_num (int): Number of port in
            _nfv_sw_port_num(int): Number of port out
            _mac(str): MAC address of the valve/port combo

        """
        return [self.port_acl_table.flowdel(
            match=self.port_acl_table.match(
                in_port=port_num,
                eth_type=valve_of.ether.ETH_TYPE_IP,
                nw_proto=valve_of.inet.IPPROTO_UDP,
                udp_src=68,
                udp_dst=67,
            ),
            priority=self.low_priority,
            strict=True
        )]

    def build_tunnel_rules_ofmsgs(self, source_id, tunnel_id, acl):
        """Build a tunnel only generated rule"""
        ofmsgs = []
        acl_table = self.port_acl_table
        priority = self.override_priority
        ofmsgs.extend(build_tunnel_ofmsgs(
            acl.dyn_tunnel_rules[tunnel_id][source_id], acl_table, priority,
            None, tunnel_id, flowdel=True))
        return ofmsgs

    def build_tunnel_acl_rule_ofmsgs(self, source_id, tunnel_id, acl):
        """Build a rule of an ACL that contains a tunnel"""
        ofmsgs = []
        acl_table = self.port_acl_table
        acl_allow_inst = self.pipeline.accept_to_vlan()
        acl_force_port_vlan_inst = self.pipeline.accept_to_l2_forwarding()
        rules = acl.get_tunnel_rules(tunnel_id)
        for rule_conf in rules:
            rule_index = acl.rules.index(rule_conf)
            priority = self.acl_priority - rule_index
            in_port = acl.tunnel_sources[source_id]['port']
            ofmsgs.extend(build_rule_ofmsgs(
                rule_conf, acl_table, acl_allow_inst, acl_force_port_vlan_inst,
                self.acl_priority, priority, self.meters,
                acl.exact_match, in_port, None, acl.dyn_tunnel_rules, source_id, flowdel=True))
        return ofmsgs

    def change_meters(self, changed_meters):
        """Change existing meters with same name/ID."""
        ofmsgs = []
        if changed_meters:
            for changed_meter in changed_meters:
                ofmsgs.append(valve_of.meteradd(
                    self.meters.get(changed_meter).entry, command=1))
        return ofmsgs

    def add_meters(self, added_meters):
        """Add new meters."""
        ofmsgs = []
        if added_meters:
            for added_meter in added_meters:
                ofmsgs.append(valve_of.meteradd(
                    self.meters.get(added_meter).entry, command=0))
        return ofmsgs

    def del_meters(self, deleted_meters):
        ofmsgs = []
        if deleted_meters:
            deleted_meter_ids = [
                self.meters[meter_key].meter_id for meter_key in deleted_meters]
            ofmsgs.extend([
                valve_of.meterdel(deleted_meter_id) for deleted_meter_id in deleted_meter_ids])
        return ofmsgs
