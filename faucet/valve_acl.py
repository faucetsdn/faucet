"""Compose ACLs on ports."""

# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
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
# distributed under the License is distributed on an "AS IS" BASIS
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

try:
    import valve_of
except ImportError:
    from faucet import valve_of


def push_vlan(vlan_vid):
    """Push a VLAN tag with optional selection of eth type."""
    vid = vlan_vid
    vlan_eth_type = None
    if isinstance(vlan_vid, dict):
        vid = vlan_vid['vid']
        if 'eth_type' in vlan_vid:
            vlan_eth_type = vlan_vid['eth_type']
    if vlan_eth_type is None:
        return valve_of.push_vlan_act(vid)
    return valve_of.push_vlan_act(vid, eth_type=vlan_eth_type)


def rewrite_vlan(output_dict):
    """Implement actions to rewrite VLAN headers."""
    vlan_actions = []
    if 'pop_vlans' in output_dict:
        for _ in range(output_dict['pop_vlans']):
            vlan_actions.append(valve_of.pop_vlan())
    # if vlan tag is specified, push it.
    if 'vlan_vid' in output_dict:
        vlan_actions.extend(push_vlan(output_dict['vlan_vid']))
    # swap existing VID
    elif 'swap_vid' in output_dict:
        vlan_actions.append(
            valve_of.set_vlan_vid(output_dict['swap_vid']))
    # or, if a list, push them all (all with type Q).
    elif 'vlan_vids' in output_dict:
        for vlan_vid in output_dict['vlan_vids']:
            vlan_actions.extend(push_vlan(vlan_vid))
    return vlan_actions


def build_output_actions(output_dict):
    """Implement actions to alter packet/output."""
    output_actions = []
    output_port = None
    ofmsgs = []
    # if destination rewriting selected, rewrite it.
    if 'dl_dst' in output_dict:
        output_actions.append(
            valve_of.set_eth_dst(output_dict['dl_dst']))
    # rewrite any VLAN headers.
    vlan_actions = rewrite_vlan(output_dict)
    if vlan_actions:
        output_actions.extend(vlan_actions)
    if 'port' in output_dict:
        output_port = output_dict['port']
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
    return (output_port, output_actions, ofmsgs)


# TODO: change this, maybe this can be rewritten easily
# possibly replace with a class for ACLs
def build_acl_entry(rule_conf, acl_allow_inst, meters, port_num=None, vlan_vid=None):
    acl_inst = []
    match_dict = {}
    ofmsgs = []
    for attrib, attrib_value in list(rule_conf.items()):
        if attrib == 'in_port':
            continue
        if attrib == 'actions':
            allow = False
            allow_specified = False
            if 'allow' in attrib_value:
                allow_specified = True
                if attrib_value['allow'] == 1:
                    allow = True
            if 'meter' in attrib_value:
                meter_name = attrib_value['meter']
                acl_inst.append(valve_of.apply_meter(meters[meter_name].meter_id))
            if 'mirror' in attrib_value:
                port_no = attrib_value['mirror']
                acl_inst.append(
                    valve_of.apply_actions([valve_of.output_port(port_no)]))
                if not allow_specified:
                    allow = True
            if 'output' in attrib_value:
                output_port, output_actions, output_ofmsgs = build_output_actions(attrib_value['output'])
                acl_inst.append(valve_of.apply_actions(output_actions))
                ofmsgs.extend(output_ofmsgs)

                # if port specified, output packet now and exit pipeline.
                if output_port is not None:
                    continue

            if allow:
                acl_inst.append(acl_allow_inst)
        else:
            match_dict[attrib] = attrib_value
    if port_num is not None:
        match_dict['in_port'] = port_num
    if vlan_vid is not None:
        match_dict['vlan_vid'] = valve_of.vid_present(vlan_vid)
    acl_match = valve_of.match_from_dict(match_dict)
    return (acl_match, acl_inst, ofmsgs)


def build_acl_ofmsgs(acls, acl_table, acl_allow_inst,
                     highest_priority, meters,
                     port_num=None, vlan_vid=None):
    ofmsgs = []
    acl_rule_priority = highest_priority
    for acl in acls:
        for rule_conf in acl.rules:
            acl_match, acl_inst, acl_ofmsgs = build_acl_entry(
                rule_conf, acl_allow_inst, meters, port_num, vlan_vid)
            ofmsgs.extend(acl_ofmsgs)
            ofmsgs.append(acl_table.flowmod(
                acl_match, priority=acl_rule_priority, inst=acl_inst))
            acl_rule_priority -= 1
    return ofmsgs
