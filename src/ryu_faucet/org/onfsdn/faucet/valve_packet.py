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
from ryu.lib.packet import ethernet, packet, vlan


def build_pkt_header(eth_src, eth_dst, vid, dl_type):
    pkt_header = packet.Packet()
    if vid is None:
        eth_header = ethernet.ethernet(
            eth_dst, eth_src, dl_type)
        pkt_header.add_protocol(eth_header)
    else:
        eth_header = ethernet.ethernet(
            eth_dst, eth_src, ether.ETH_TYPE_8021Q)
        pkt_header.add_protocol(eth_header)
        vlan_header = vlan.vlan(vid=vid, ethertype=dl_type)
        pkt_header.add_protocol(vlan_header)
    return pkt_header
