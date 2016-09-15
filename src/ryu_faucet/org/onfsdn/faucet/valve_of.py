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

from ryu.ofproto import ether
from ryu.ofproto import ofproto_v1_3 as ofp
from ryu.ofproto import ofproto_v1_3_parser as parser


def ignore_port(port_num):
    """Ignore non-physical ports."""
    # port numbers > 0xF0000000 indicate a logical port
    return port_num > 0xF0000000

def apply_actions(actions):
    return parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)

def goto_table(table_id):
    return parser.OFPInstructionGotoTable(table_id)

def set_eth_src(eth_src):
    return parser.OFPActionSetField(eth_src=eth_src)

def set_eth_dst(eth_dst):
    return parser.OFPActionSetField(eth_dst=eth_dst)

def push_vlan_act(vlan_vid):
    return [
        parser.OFPActionPushVlan(ether.ETH_TYPE_8021Q),
        parser.OFPActionSetField(vlan_vid=(vlan_vid | ofp.OFPVID_PRESENT))
    ]

def dec_ip_ttl():
    return parser.OFPActionDecNwTtl()

def pop_vlan():
    return parser.OFPActionPopVlan()

def output_port(port_no, max_len=0):
    return parser.OFPActionOutput(port_no, max_len=max_len)

def output_controller():
    return output_port(ofp.OFPP_CONTROLLER, 256)

def packetout(out_port, data):
    return parser.OFPPacketOut(
        datapath=None,
        buffer_id=ofp.OFP_NO_BUFFER,
        in_port=ofp.OFPP_CONTROLLER,
        actions=[output_port(out_port)],
        data=data)
