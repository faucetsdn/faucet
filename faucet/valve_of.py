"""Utility functions to parse/create OpenFlow messages."""

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

import ipaddress

from ryu.lib import mac
from ryu.lib import ofctl_v1_3 as ofctl
from ryu.lib.ofctl_utils import str_to_int, to_match_ip, to_match_masked_int, to_match_eth, to_match_vid, OFCtlUtil
from ryu.ofproto import ether
from ryu.ofproto import inet
from ryu.ofproto import ofproto_v1_3 as ofp
from ryu.ofproto import ofproto_v1_3_parser as parser

VLAN_GROUP_OFFSET = 4096
ROUTE_GROUP_OFFSET = VLAN_GROUP_OFFSET * 2
OFP_VERSIONS = [ofp.OFP_VERSION]
OFP_IN_PORT = ofp.OFPP_IN_PORT


def ignore_port(port_num):
    """Return True if FAUCET should ignore this port.

    Args:
        port_num (int): switch port.
    Returns:
        bool: True if FAUCET should ignore this port.
    """
    # 0xF0000000 and up are not physical ports.
    return port_num > 0xF0000000


def is_flowmod(ofmsg):
    """Return True if flow message is a FlowMod.

    Args:
        ofmsg: ryu.ofproto.ofproto_v1_3_parser message.
    Returns:
        bool: True if is a FlowMod
    """
    return isinstance(ofmsg, parser.OFPFlowMod)


def is_groupmod(ofmsg):
    """Return True if OF message is a GroupMod.

    Args:
        ofmsg: ryu.ofproto.ofproto_v1_3_parser message.
    Returns:
        bool: True if is a GroupMod
    """
    return isinstance(ofmsg, parser.OFPGroupMod)


def is_flowdel(ofmsg):
    """Return True if flow message is a FlowMod and a delete.

    Args:
        ofmsg: ryu.ofproto.ofproto_v1_3_parser message.
    Returns:
        bool: True if is a FlowMod delete/strict.
    """
    if (is_flowmod(ofmsg) and
            (ofmsg.command == ofp.OFPFC_DELETE or
             ofmsg.command == ofp.OFPFC_DELETE_STRICT)):
        return True
    return False


def is_groupdel(ofmsg):
    """Return True if OF message is a GroupMod and command is delete.

    Args:
        ofmsg: ryu.ofproto.ofproto_v1_3_parser message.
    Returns:
        bool: True if is a GroupMod delete
    """
    if (is_groupmod(ofmsg) and
            (ofmsg.command == ofp.OFPGC_DELETE)):
        return True
    return False


def is_groupadd(ofmsg):
    """Return True if OF message is a GroupMod and command is add.

    Args:
        ofmsg: ryu.ofproto.ofproto_v1_3_parser message.
    Returns:
        bool: True if is a GroupMod add
    """
    if (is_groupmod(ofmsg) and
            (ofmsg.command == ofp.OFPGC_ADD)):
        return True
    return False


def apply_meter(meter_id):
    """Return instruction to apply a meter."""
    return parser.OFPInstructionMeter(meter_id, ofp.OFPIT_METER)


def apply_actions(actions):
    """Return instruction that applies action list.

    Args:
        actions (list): list of OpenFlow actions.
    Returns:
        ryu.ofproto.ofproto_v1_3_parser.OFPInstruction: instruction of actions.
    """
    return parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)


def goto_table(table):
    """Return instruction to goto table.

    Args:
        table (ValveTable): table to goto.
    Returns:
        ryu.ofproto.ofproto_v1_3_parser.OFPInstruction: goto instruction.
    """
    return parser.OFPInstructionGotoTable(table.table_id)


def set_eth_src(eth_src):
    """Return action to set source Ethernet MAC address.

    Args:
        eth_src (str): source Ethernet MAC address.
    Returns:
        ryu.ofproto.ofproto_v1_3_parser.OFPActionSetField: set field action.
    """
    return parser.OFPActionSetField(eth_src=eth_src)


def set_eth_dst(eth_dst):
    """Return action to set destination Ethernet MAC address.

    Args:
        eth_src (str): destination Ethernet MAC address.
    Returns:
        ryu.ofproto.ofproto_v1_3_parser.OFPActionSetField: set field action.
    """
    return parser.OFPActionSetField(eth_dst=eth_dst)


def vid_present(vid):
    """Return VLAN VID with VID_PRESENT flag set.

    Args:
        vid (int): VLAN VID
    Returns:
        int: VLAN VID with VID_PRESENT.
    """
    return vid | ofp.OFPVID_PRESENT


def devid_present(vid):
    """Return VLAN VID without VID_PRESENT flag set.

    Args:
        vid (int): VLAN VID with VID_PRESENT.
    Returns:
        int: VLAN VID.
    """
    return vid ^ ofp.OFPVID_PRESENT


def set_vlan_vid(vlan_vid):
    """Set VLAN VID with VID_PRESENT flag set.

    Args:
        vid (int): VLAN VID
    Returns:
        ryu.ofproto.ofproto_v1_3_parser.OFPActionSetField: set VID with VID_PRESENT.
    """
    return parser.OFPActionSetField(vlan_vid=vid_present(vlan_vid))


def push_vlan_act(vlan_vid, eth_type=ether.ETH_TYPE_8021Q):
    """Return OpenFlow action list to push Ethernet 802.1Q header with VLAN VID.

    Args:
        vid (int): VLAN VID
    Returns:
        list: actions to push 802.1Q header with VLAN VID set.
    """
    return [
        parser.OFPActionPushVlan(eth_type),
        set_vlan_vid(vlan_vid),
    ]


def dec_ip_ttl():
    """Return OpenFlow action to decrement IP TTL.

    Returns:
        ryu.ofproto.ofproto_v1_3_parser.OFPActionDecNwTtl: decrement IP TTL.
    """
    return parser.OFPActionDecNwTtl()


def pop_vlan():
    """Return OpenFlow action to pop outermost Ethernet 802.1Q VLAN header.

    Returns:
        ryu.ofproto.ofproto_v1_3_parser.OFPActionPopVlan: Pop VLAN.
    """
    return parser.OFPActionPopVlan()


def output_port(port_num, max_len=0):
    """Return OpenFlow action to output to a port.

    Args:
        port_num (int): port to output to.
        max_len (int): maximum length of packet to output (default no maximum).
    Returns:
        ryu.ofproto.ofproto_v1_3_parser.OFPActionOutput: output to port action.
    """
    return parser.OFPActionOutput(port_num, max_len=max_len)


def output_in_port():
    """Return OpenFlow action to output out input port.

    Returns:
       ryu.ofproto.ofproto_v1_3_parser.OFPActionOutput.
    """
    return output_port(OFP_IN_PORT)


def output_controller(max_len=96):
    """Return OpenFlow action to packet in to the controller.

    Args:
        max_len (int): max number of bytes from packet to output.
    Returns:
        ryu.ofproto.ofproto_v1_3_parser.OFPActionOutput: packet in action.
    """
    return output_port(ofp.OFPP_CONTROLLER, max_len)


def packetout(port_num, data):
    """Return OpenFlow action to packet out to dataplane from controller.

    Args:
        port_num (int): port to output to.
        data (str): raw packet to output.
    Returns:
        ryu.ofproto.ofproto_v1_3_parser.OFPActionOutput: packet out action.
    """
    return parser.OFPPacketOut(
        datapath=None,
        buffer_id=ofp.OFP_NO_BUFFER,
        in_port=ofp.OFPP_CONTROLLER,
        actions=[output_port(port_num)],
        data=data)


def barrier():
    """Return OpenFlow barrier request.

    Returns:
        ryu.ofproto.ofproto_v1_3_parser.OFPBarrierRequest: barrier request.
    """
    return parser.OFPBarrierRequest(None)


def table_features(body):
    return parser.OFPTableFeaturesStatsRequest(
        datapath=None, body=body)


def match(match_fields):
    """Return OpenFlow matches from dict.

    Args:
        match_fields (dict): match fields and values.
    Returns:
        ryu.ofproto.ofproto_v1_3_parser.OFPMatch: matches.
    """
    return parser.OFPMatch(**match_fields)


def valve_match_vid(value):
    return to_match_vid(value, ofp.OFPVID_PRESENT)


def match_from_dict(match_dict):
    convert = {
        'in_port': OFCtlUtil(ofp).ofp_port_from_user,
        'in_phy_port': str_to_int,
        'metadata': to_match_masked_int,
        'dl_dst': to_match_eth,
        'dl_src': to_match_eth,
        'eth_dst': to_match_eth,
        'eth_src': to_match_eth,
        'dl_type': str_to_int,
        'eth_type': str_to_int,
        'dl_vlan': valve_match_vid,
        'vlan_vid': valve_match_vid,
        'vlan_pcp': str_to_int,
        'ip_dscp': str_to_int,
        'ip_ecn': str_to_int,
        'nw_proto': str_to_int,
        'ip_proto': str_to_int,
        'nw_src': to_match_ip,
        'nw_dst': to_match_ip,
        'ipv4_src': to_match_ip,
        'ipv4_dst': to_match_ip,
        'tp_src': to_match_masked_int,
        'tp_dst': to_match_masked_int,
        'tcp_src': to_match_masked_int,
        'tcp_dst': to_match_masked_int,
        'udp_src': to_match_masked_int,
        'udp_dst': to_match_masked_int,
        'sctp_src': to_match_masked_int,
        'sctp_dst': to_match_masked_int,
        'icmpv4_type': str_to_int,
        'icmpv4_code': str_to_int,
        'arp_op': str_to_int,
        'arp_spa': to_match_ip,
        'arp_tpa': to_match_ip,
        'arp_sha': to_match_eth,
        'arp_tha': to_match_eth,
        'ipv6_src': to_match_ip,
        'ipv6_dst': to_match_ip,
        'ipv6_flabel': str_to_int,
        'icmpv6_type': str_to_int,
        'icmpv6_code': str_to_int,
        'ipv6_nd_target': to_match_ip,
        'ipv6_nd_sll': to_match_eth,
        'ipv6_nd_tll': to_match_eth,
        'mpls_label': str_to_int,
        'mpls_tc': str_to_int,
        'mpls_bos': str_to_int,
        'pbb_isid': to_match_masked_int,
        'tunnel_id': to_match_masked_int,
        'ipv6_exthdr': to_match_masked_int
    }

    old_keys = {
        'dl_dst': 'eth_dst',
        'dl_src': 'eth_src',
        'dl_type': 'eth_type',
        'dl_vlan': 'vlan_vid',
        'nw_src': 'ipv4_src',
        'nw_dst': 'ipv4_dst',
        'nw_proto': 'ip_proto'
    }

    if (match_dict.get('dl_type') == ether.ETH_TYPE_ARP or
            match_dict.get('eth_type') == ether.ETH_TYPE_ARP):
        if 'nw_src' in match_dict and 'arp_spa' not in match_dict:
            match_dict['arp_spa'] = match_dict['nw_src']
            del match_dict['nw_src']
        if 'nw_dst' in match_dict and 'arp_tpa' not in match_dict:
            match_dict['arp_tpa'] = match_dict['nw_dst']
            del match_dict['nw_dst']

    kwargs = {}
    for key, value in list(match_dict.items()):
        if key in old_keys:
            # For old field name
            key = old_keys[key]
        assert key in convert, 'Unknown match field: %s' % key
        value = convert[key](value)
        if key == 'tp_src' or key == 'tp_dst':
            # TCP/UDP port
            conv = {inet.IPPROTO_TCP: {'tp_src': 'tcp_src',
                                       'tp_dst': 'tcp_dst'},
                    inet.IPPROTO_UDP: {'tp_src': 'udp_src',
                                       'tp_dst': 'udp_dst'}}
            ip_proto = match_dict.get(
                'nw_proto', match_dict.get('ip_proto', 0))
            key = conv[ip_proto][key]
        kwargs[key] = value

    return parser.OFPMatch(**kwargs)


def _match_ip_masked(ipa):
    if isinstance(ipa, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
        return (str(ipa.network_address), str(ipa.netmask))
    return (str(ipa.ip), str(ipa.netmask))


def build_match_dict(in_port=None, vlan=None,
                     eth_type=None, eth_src=None,
                     eth_dst=None, eth_dst_mask=None,
                     ipv6_nd_target=None, icmpv6_type=None,
                     nw_proto=None,
                     nw_src=None, nw_dst=None):
    match_dict = {}
    if in_port is not None:
        match_dict['in_port'] = in_port
    if vlan is not None:
        if vlan.vid == ofp.OFPVID_NONE:
            match_dict['vlan_vid'] = int(ofp.OFPVID_NONE)
        elif vlan.vid == ofp.OFPVID_PRESENT:
            match_dict['vlan_vid'] = (ofp.OFPVID_PRESENT, ofp.OFPVID_PRESENT)
        else:
            match_dict['vlan_vid'] = vid_present(vlan.vid)
    if eth_src is not None:
        match_dict['eth_src'] = eth_src
    if eth_dst is not None:
        if eth_dst_mask is not None:
            match_dict['eth_dst'] = (eth_dst, eth_dst_mask)
        else:
            match_dict['eth_dst'] = eth_dst
    if nw_proto is not None:
        match_dict['ip_proto'] = nw_proto
    if nw_src is not None:
        match_dict['ipv4_src'] = _match_ip_masked(nw_src)
    if icmpv6_type is not None:
        match_dict['icmpv6_type'] = icmpv6_type
    if ipv6_nd_target is not None:
        match_dict['ipv6_nd_target'] = str(ipv6_nd_target.ip)
    if nw_dst is not None:
        nw_dst_masked = _match_ip_masked(nw_dst)
        if eth_type == ether.ETH_TYPE_ARP:
            match_dict['arp_tpa'] = str(nw_dst.ip)
        elif eth_type == ether.ETH_TYPE_IP:
            match_dict['ipv4_dst'] = nw_dst_masked
        else:
            match_dict['ipv6_dst'] = nw_dst_masked
    if eth_type is not None:
        match_dict['eth_type'] = eth_type
    return match_dict


def flowmod(cookie, command, table_id, priority, out_port, out_group,
            match_fields, inst, hard_timeout, idle_timeout, flags=0):
    return parser.OFPFlowMod(
        datapath=None,
        cookie=cookie,
        command=command,
        table_id=table_id,
        priority=priority,
        out_port=out_port,
        out_group=out_group,
        match=match_fields,
        instructions=inst,
        hard_timeout=hard_timeout,
        idle_timeout=idle_timeout,
        flags=flags)


def group_act(group_id):
    """Return an action to run a group."""
    return parser.OFPActionGroup(group_id)


def bucket(weight=0, watch_port=ofp.OFPP_ANY,
           watch_group=ofp.OFPG_ANY, actions=None):
    """Return a group action bucket with provided actions."""
    return parser.OFPBucket(
        weight=weight,
        watch_port=watch_port,
        watch_group=watch_group,
        actions=actions)


def groupmod(datapath=None, type_=ofp.OFPGT_ALL, group_id=0, buckets=None):
    """Modify a group."""
    return parser.OFPGroupMod(
        datapath,
        ofp.OFPGC_MODIFY,
        type_,
        group_id,
        buckets)


def groupmod_ff(datapath=None, group_id=0, buckets=None):
    """Modify a fast failover group."""
    return groupmod(datapath, type_=ofp.OFPGT_FF, group_id=group_id, buckets=buckets)


def groupadd(datapath=None, type_=ofp.OFPGT_ALL, group_id=0, buckets=None):
    """Add a group."""
    return parser.OFPGroupMod(
        datapath,
        ofp.OFPGC_ADD,
        type_,
        group_id,
        buckets)


def groupadd_ff(datapath=None, group_id=0, buckets=None):
    """Add a fast failover group."""
    return groupadd(datapath, type_=ofp.OFPGT_FF, group_id=group_id, buckets=buckets)


def groupdel(datapath=None, group_id=ofp.OFPG_ALL):
    """Delete a group (default all groups)."""
    return parser.OFPGroupMod(
        datapath,
        ofp.OFPGC_DELETE,
        0,
        group_id)


def meterdel(datapath=None, meter_id=ofp.OFPM_ALL):
    """Delete a meter (default all meters)."""
    return parser.OFPMeterMod(
        datapath,
        ofp.OFPMC_DELETE,
        0,
        meter_id)


def meteradd(meter_conf):
    """Add a meter based on YAML configuration."""

    class NoopDP(object):
        """Fake DP to be able to use ofctl to parse meter config."""

        id = 0
        msg = None
        ofproto = ofp
        ofproto_parser = parser

        def send_msg(self, msg):
            """Save msg only."""
            self.msg = msg

        @staticmethod
        def set_xid(msg):
            """Clear msg XID."""
            msg.xid = 0

    noop_dp = NoopDP()
    ofctl.mod_meter_entry(noop_dp, meter_conf, ofp.OFPMC_ADD)
    noop_dp.msg.xid = None
    noop_dp.msg.datapath = None
    return noop_dp.msg


def controller_pps_meteradd(datapath=None, pps=0):
    """Add a PPS meter towards controller."""
    return parser.OFPMeterMod(
        datapath=datapath,
        command=ofp.OFPMC_ADD,
        flags=ofp.OFPMF_PKTPS,
        meter_id=ofp.OFPM_CONTROLLER,
        bands=[parser.OFPMeterBandDrop(rate=pps)])


def controller_pps_meterdel(datapath=None):
    """Delete a PPS meter towards controller."""
    return parser.OFPMeterMod(
        datapath=datapath,
        command=ofp.OFPMC_DELETE,
        flags=ofp.OFPMF_PKTPS,
        meter_id=ofp.OFPM_CONTROLLER)


def valve_flowreorder(input_ofmsgs):
    """Reorder flows for better OFA performance."""
    # Move all deletes to be first, and add one barrier,
    # while preserving order. Platforms that do parallel delete
    # will perform better and platforms that don't will have
    # at most only one barrier to deal with.
    # TODO: further optimizations may be possible - for example,
    # reorder adds to be in priority order.
    delete_ofmsgs = []
    groupadd_ofmsgs = []
    nondelete_ofmsgs = []
    for ofmsg in input_ofmsgs:
        if is_flowdel(ofmsg) or is_groupdel(ofmsg):
            delete_ofmsgs.append(ofmsg)
        elif is_groupadd(ofmsg):
            # The same group_id may be deleted/added multiple times
            # To avoid group_mod_failed/group_exists error, if the
            # same group_id is already in groupadd_ofmsgs I replace
            # it instead of appending it (the last groupadd in
            # input_ofmsgs is the only one sent to the switch)
            # TODO: optimize the provisioning to avoid having the
            # same group_id multiple times in input_ofmsgs
            new_group_id = True
            for i, groupadd_ofmsg in enumerate(groupadd_ofmsgs):
                if groupadd_ofmsg.group_id == ofmsg.group_id:
                    groupadd_ofmsgs[i] = ofmsg
                    new_group_id = False
                    break
            if new_group_id:
                groupadd_ofmsgs.append(ofmsg)
        else:
            nondelete_ofmsgs.append(ofmsg)
    output_ofmsgs = []
    if delete_ofmsgs:
        output_ofmsgs.extend(delete_ofmsgs)
        output_ofmsgs.append(barrier())
    if groupadd_ofmsgs:
        output_ofmsgs.extend(groupadd_ofmsgs)
        output_ofmsgs.append(barrier())
    output_ofmsgs.extend(nondelete_ofmsgs)
    return output_ofmsgs


def group_flood_buckets(ports, untagged):
    buckets = []
    for port in ports:
        out_actions = []
        if untagged:
            out_actions.append(pop_vlan())
        out_actions.append(output_port(port.number))
        buckets.append(bucket(actions=out_actions))
    return buckets


def flood_tagged_port_outputs(ports, in_port, exclude_ports=None):
    """Return list of actions necessary to flood to list of tagged ports."""
    flood_acts = []
    if ports:
        for port in ports:
            if port == in_port:
                if port.hairpin:
                    flood_acts.append(output_in_port())
                continue
            if exclude_ports and port in exclude_ports:
                continue
            flood_acts.append(output_port(port.number))
    return flood_acts


def flood_untagged_port_outputs(ports, in_port, exclude_ports=None):
    """Return list of actions necessary to flood to list of untagged ports."""
    flood_acts = []
    if ports:
        flood_acts.append(pop_vlan())
        flood_acts.extend(flood_tagged_port_outputs(
            ports, in_port, exclude_ports=exclude_ports))
    return flood_acts
