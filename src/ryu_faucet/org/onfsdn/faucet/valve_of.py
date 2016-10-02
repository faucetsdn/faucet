"""Utility functions to parse/create OpenFlow messages."""

# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2015 Brad Cowie, Christopher Lorier and Joe Stringer.
# Copyright (C) 2015 Research and Education Advanced Network New Zealand Ltd.
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

from ryu.lib import ofctl_v1_3 as ofctl
from ryu.ofproto import ether
from ryu.ofproto import ofproto_v1_3 as ofp
from ryu.ofproto import ofproto_v1_3_parser as parser


def ignore_port(port_num):
    """Return True if FAUCET should ignore this port.

    Args:
        port_num (int): switch port.
    Returns:
        bool: True if FAUCET should ignore this port.
    """
    # 0xF0000000 and up are not physical ports.
    return port_num > 0xF0000000


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


def push_vlan_act(vlan_vid):
    """Return OpenFlow action list to push Ethernet 802.1Q header with VLAN VID.

    Args:
        vid (int): VLAN VID
    Returns:
        list: actions to push 802.1Q header with VLAN VID set.
    """
    return [
        parser.OFPActionPushVlan(ether.ETH_TYPE_8021Q),
        parser.OFPActionSetField(vlan_vid=vid_present(vlan_vid))
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


def output_controller():
    """Return OpenFlow action to packet in to the controller (max 256 bytes).

    Returns:
        ryu.ofproto.ofproto_v1_3_parser.OFPActionOutput: packet in action.
    """
    return output_port(ofp.OFPP_CONTROLLER, 256)


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


def match(match):
    """Return OpenFlow matches from dict.

    Args:
        match (dict): match fields and values.
    Returns:
        ryu.ofproto.ofproto_v1_3_parser.OFPMatch: matches.
    """
    return parser.OFPMatch(**match)


def match_from_dict(match_dict):
    null_dp = namedtuple('null_dp', 'ofproto_parser')
    null_dp.ofproto_parser = parser
    acl_match = ofctl.to_match(null_dp, match_dict)
    return acl_match


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
        match_dict['ipv4_src'] = (str(nw_src.ip), str(nw_src.netmask))
    if icmpv6_type is not None:
        match_dict['icmpv6_type'] = icmpv6_type
    if ipv6_nd_target is not None:
        match_dict['ipv6_nd_target'] = str(ipv6_nd_target.ip)
    if nw_dst is not None:
        nw_dst_masked = (str(nw_dst.ip), str(nw_dst.netmask))
        if eth_type == ether.ETH_TYPE_ARP:
            match_dict['arp_tpa'] = nw_dst_masked
        elif eth_type == ether.ETH_TYPE_IP:
            match_dict['ipv4_dst'] = nw_dst_masked
        else:
            match_dict['ipv6_dst'] = nw_dst_masked
    if eth_type is not None:
        match_dict['eth_type'] = eth_type
    return match_dict


def flowmod(cookie, command, table_id, priority, out_port, out_group,
            match, inst, hard_timeout, idle_timeout):
    return parser.OFPFlowMod(
        datapath=None,
        cookie=cookie,
        command=command,
        table_id=table_id,
        priority=priority,
        out_port=out_port,
        out_group=out_group,
        match=match,
        instructions=inst,
        hard_timeout=hard_timeout,
        idle_timeout=idle_timeout)
