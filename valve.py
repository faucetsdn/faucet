# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import struct, yaml

from ryu.base import app_manager
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib import addrconv
from ryu.lib import igmplib
from ryu.lib.dpid import str_to_dpid

class Valve(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]
    _CONTEXTS = {'igmplib': igmplib.IgmpLib}

    def __init__(self, *args, **kwargs):
        super(SimpleSwitchIgmp, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self._snoop = kwargs['igmplib']
        # if you want a switch to operate as a querier,
        # set up as follows:
        self._snoop.set_querier_mode(
            dpid=str_to_dpid('0000000000000001'), server_port=2)
        # dpid         the datapath id that will operate as a querier.
        # server_port  a port number which connect to the multicast
        #              server.
        #
        # NOTE: you can set up only the one querier.
        # when you called this method several times,
        # only the last one becomes effective.

        # Read in config file
        self.portdb = None
        self.vlandb = {}

        with open('valve.yaml', 'r') as stream:
            portdb = yaml.load(stream)

        for port in portdb:
            vlans = portdb[port]['vlan']
            ptype = portdb[port]['type']
            if type(vlans) is list:
                for vlan in vlans:
                   if vlan not in vlandb:
                       vlandb[vlan] = {'tagged': [], 'untagged': []}
                   vlandb[vlan][ptype].append(port)
            else:
                if vlans not in vlandb:
                    vlandb[vlans] = {'tagged': [], 'untagged': []}
                vlandb[vlans][ptype].append(port)

    def add_flow(self, datapath, match, actions):
        ofproto = datapath.ofproto
        mod = parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, actions=actions)
        datapath.send_msg(mod)

    @set_ev_cls(igmplib.EventPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        (dst_, src_, _eth_type) = struct.unpack_from(
            '!6s6sH', buffer(msg.data), 0)
        src = addrconv.mac.bin_to_text(src_)
        dst = addrconv.mac.bin_to_text(dst_)

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # find the in_port:
        # TODO: allow this to support more than one dp
        in_port = msg.in_port

        # TODO: actually discover the vlan rather than it always being the
        # same
        vlan = self.portdb[in_port]['vlan'][0]
        self.mac_to_port[dpid].setdefault(vlan, {})

        self.logger.info("packet in %s %s %s %d",
                         dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][vlan][src] = in_port

        if dst in self.mac_to_port[dpid]:
            # install a flow to avoid packet_in next time
            out_port = self.mac_to_port[dpid][vlan][dst]

            # ok so if it comes in an access port and goes out an access port
            # then we dont need to do anything about tags
            # if it comes in a trunk we need to match the tag
            # if it comes in an access we need to push the tag
            if in_port['type'] == 'tagged':
                match = parser.OFPMatch(
                    in_port=in_port,
                    dl_src=addrconv.mac.text_to_bin(src),
                    dl_dst=addrconv.mac.text_to_bin(dst),
                    dl_vlan=vlan)
                actions = []
                if out_port['type'] == 'untagged':
                    actions.append(
                        parser.OFPActionStripVlan())
            if in_port['type'] == 'untagged':
                match = parser.OFPMatch(
                    in_port=in_port,
                    dl_src=addrconv.mac.text_to_bin(src),
                    dl_dst=addrconv.mac.text_to_bin(dst))
                if out_port['type'] == 'tagged':
                    actions.append(parser.OFPActionVlanVid(vlan))
            actions.append(parser.OFPActionOutput(out_port))

            self.add_flow(datapath, match, actions)
        else:
            # generates an action to flood a packet to every port with this
            # vlan configured
            # this is dependent on whether the packet is already tagged
            access_actions = []
            trunk_actions = []
            for out_port in self.vlandb[vlan]['untagged']:
                if in_port != out_port:
                    access_actions.append(
                            parser.OFPActionOutput(out_port))

            for out_port in self.vlandb[vlan]['tagged']:
                if in_port != out_port:
                    trunk_actions.append(
                            parser.OFPActionOutput(out_port))

            if self.portdb[in_port]['type'] == 'tagged':
                strip_action = [parser.OFPActionStripVlan()]
                actions = trunk_actions + strip_action + access_actions
            else:
                push_action = [parser.OFPActionVlanVid(vlan)]
                actions = access_actions + push_action + trunk_actions

        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions)
        datapath.send_msg(out)

    @set_ev_cls(igmplib.EventMulticastGroupStateChanged,
                MAIN_DISPATCHER)
    def _status_changed(self, ev):
        msg = {
            igmplib.MG_GROUP_ADDED: 'Multicast Group Added',
            igmplib.MG_MEMBER_CHANGED: 'Multicast Group Member Changed',
            igmplib.MG_GROUP_REMOVED: 'Multicast Group Removed',
        }
        self.logger.info("%s: [%s] querier:[%s] hosts:%s",
                         msg.get(ev.reason), ev.address, ev.src,
                         ev.dsts)
