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
# distributed under the License is distributed on an "AS IS" BASISo
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from collections import namedtuple
import ipaddress

from ryu.lib import ofctl_v1_3 as ofctl
from ryu.ofproto import ether
from ryu.ofproto import ofproto_v1_3 as ofp
from ryu.ofproto import ofproto_v1_3_parser as parser


VLAN_GROUP_OFFSET = 4096
ROUTE_GROUP_OFFSET = VLAN_GROUP_OFFSET * 2
OFP_VERSIONS = [ofp.OFP_VERSION]


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


def apply_actions(actions):
    """Return instruction that applies action list.

    Args:
        actions (list): list of OpenFlow actions.
    Returns:
        ryu.ofproto.ofproto_v1_3_parser.OFPInstruction: instruction of actions.
    """
    return parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)


def goto_table(table_id):
    """Return instruction to goto table.

    Args:
        table_id (int): table to goto.
    Returns:
        ryu.ofproto.ofproto_v1_3_parser.OFPInstruction: goto instruction.
    """
    return parser.OFPInstructionGotoTable(table_id)


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
    return output_port(ofp.OFPP_IN_PORT)


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


def match_from_dict(match_dict):
    null_dp = namedtuple('null_dp', 'ofproto_parser')
    null_dp.ofproto_parser = parser
    acl_match = ofctl.to_match(null_dp, match_dict)
    return acl_match


def _match_ip_masked(ipa):
    if (isinstance(ipa, ipaddress.IPv4Network) or
            isinstance(ipa, ipaddress.IPv6Network)):
        return (str(ipa.network_address), str(ipa.netmask))
    else:
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
            match_dict['vlan_vid'] = ofp.OFPVID_NONE
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
            match_fields, inst, hard_timeout, idle_timeout):
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
        idle_timeout=idle_timeout)


def group_act(group_id):
    return parser.OFPActionGroup(group_id)


def bucket(weight=0, watch_port=ofp.OFPP_ANY,
           watch_group=ofp.OFPG_ANY, actions=None):
    return parser.OFPBucket(
        weight=weight,
        watch_port=watch_port,
        watch_group=watch_group,
        actions=actions)


def groupmod(datapath=None, type_=ofp.OFPGT_ALL, group_id=0, buckets=None):
    return parser.OFPGroupMod(
        datapath,
        ofp.OFPGC_MODIFY,
        type_,
        group_id,
        buckets)


def groupadd(datapath=None, type_=ofp.OFPGT_ALL, group_id=0, buckets=None):
    return parser.OFPGroupMod(
        datapath,
        ofp.OFPGC_ADD,
        type_,
        group_id,
        buckets)


def groupdel(datapath=None, group_id=ofp.OFPG_ALL):
    return parser.OFPGroupMod(
        datapath,
        ofp.OFPGC_DELETE,
        0,
        group_id)


def controller_pps_meteradd(datapath=None, pps=0):
    return parser.OFPMeterMod(
        datapath=datapath,
        command=ofp.OFPMC_ADD,
        flags=ofp.OFPMF_PKTPS,
        meter_id=ofp.OFPM_CONTROLLER,
        bands=[parser.OFPMeterBandDrop(rate=pps)])


def controller_pps_meterdel(datapath=None):
    return parser.OFPMeterMod(
        datapath=datapath,
        command=ofp.OFPMC_DELETE,
        flags=ofp.OFPMF_PKTPS,
        meter_id=ofp.OFPM_CONTROLLER)
