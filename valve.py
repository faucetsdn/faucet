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
from ryu.controller import dpset
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib import addrconv
from ryu.lib import igmplib
from ryu.lib.dpid import str_to_dpid

HIGH_PRIORITY = 2 # Now that is what I call high
LOW_PRIORITY = 1

class Valve(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]
    _CONTEXTS = {'igmplib': igmplib.IgmpLib}

    def __init__(self, *args, **kwargs):
        super(Valve, self).__init__(*args, **kwargs)
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
            self.portdb = yaml.load(stream)

        for port in self.portdb:
            vlans = self.portdb[port]['vlans']
            ptype = self.portdb[port]['type']
            if type(vlans) is list:
                for vlan in vlans:
                   if vlan not in self.vlandb:
                       self.vlandb[vlan] = {'tagged': [], 'untagged': []}
                   self.vlandb[vlan][ptype].append(port)
            else:
                if vlans not in self.vlandb:
                    self.vlandb[vlans] = {'tagged': [], 'untagged': []}
                self.vlandb[vlans][ptype].append(port)

    def add_flow(self, datapath, match, actions, priority):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        mod = parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0, priority=priority,
            command=ofproto.OFPFC_ADD, actions=actions)
        datapath.send_msg(mod)

    @set_ev_cls(igmplib.EventPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        (dst_, src_, eth_type, vlan_) = struct.unpack_from(
            '!6s6sHH', buffer(msg.data), 0)
        src = addrconv.mac.bin_to_text(src_)
        dst = addrconv.mac.bin_to_text(dst_)

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # find the in_port:
        # TODO: allow this to support more than one dp
        in_port = msg.in_port

        if in_port not in self.portdb:
          return

        if eth_type == 0x8100:
            vlan = vlan_ & 0xFFF
            if vlan not in self.portdb[in_port]['vlans']:
                print "HAXX:RZ %d %d" % (vlan, in_port)
                return
        else:
            vlan = self.portdb[in_port]['vlans'][0]
            if self.portdb[in_port]['type'] == 'tagged':
                print "Untagged pkt_in tagged port %d" % (in_port)
                return
        self.mac_to_port[dpid].setdefault(vlan, {})

        self.logger.info("packet in %s %s %s %d",
                         dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][vlan][src] = in_port

        if dst in self.mac_to_port[dpid][vlan]:
            # install a flow to avoid packet_in next time
            out_port = self.mac_to_port[dpid][vlan][dst]
            actions = []

            if self.portdb[in_port]['type'] == 'tagged':
                match = parser.OFPMatch(
                    in_port=in_port,
                    dl_src=addrconv.mac.text_to_bin(src),
                    dl_dst=addrconv.mac.text_to_bin(dst),
                    dl_vlan=vlan)
                if self.portdb[out_port]['type'] == 'untagged':
                    actions.append(
                        parser.OFPActionStripVlan())
            if self.portdb[in_port]['type'] == 'untagged':
                match = parser.OFPMatch(
                    in_port=in_port,
                    dl_src=addrconv.mac.text_to_bin(src),
                    dl_dst=addrconv.mac.text_to_bin(dst))
                if self.portdb[out_port]['type'] == 'tagged':
                    actions.append(parser.OFPActionVlanVid(vlan))
            actions.append(parser.OFPActionOutput(out_port))

            self.add_flow(datapath, match, actions, HIGH_PRIORITY)

    @set_ev_cls(dpset.EventDP, dpset.DPSET_EV_DISPATCHER)
    def handler_datapath(self, ev):
        dp = ev.dp
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        for vid, vlan in self.vlandb.iteritems():
            controller_act = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]

            # generate the output actions for each port
            untagged_act = []
            tagged_act = []
            for port in vlan['untagged']:
                untagged_act.append(parser.OFPActionOutput(port))
            for port in vlan['tagged']:
                tagged_act.append(parser.OFPActionOutput(port))

            # send rule for matching packets arriving on tagged ports
            strip_act = [parser.OFPActionStripVlan()]
            action = controller_act + tagged_act + strip_act + untagged_act
            match = parser.OFPMatch(dl_vlan=vid)
            self.add_flow(dp, match, action, LOW_PRIORITY)

            # send rule for each untagged port
            push_act = [parser.OFPActionVlanVid(vid)]
            for port in vlan['untagged']:
                match = parser.OFPMatch(in_port=port)
                action = controller_act + untagged_act + push_act + tagged_act
                self.add_flow(dp, match, action, LOW_PRIORITY)

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
