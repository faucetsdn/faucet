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

import struct, yaml, copy, logging

from acl import ACL

from ryu.base import app_manager
from ryu.controller import dpset
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import ofctl_v1_3
from ryu.lib import igmplib
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import vlan
from ryu.lib.dpid import str_to_dpid

HIGHEST_PRIORITY = 9099
HIGH_PRIORITY = 9001 # Now that is what I call high
LOW_PRIORITY = 9000
LOWEST_PRIORITY = 0

class Valve(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
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

        # Setup logging
        handler = logging.StreamHandler()
        log_format = '%(asctime)s %(name)-8s %(levelname)-8s %(message)s'
        formatter = logging.Formatter(log_format, '%b %d %H:%M:%S')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.logger.propagate = 0

        # Read in config file
        self.portdb = None
        self.vlandb = {}
        self.acldb = {}

        with open('valve.yaml', 'r') as stream:
            self.portdb = yaml.load(stream)

        # Make sure exclude property always exists in 'default'
        if 'default' in self.portdb and 'exclude' not in self.portdb['default']:
            self.portdb['default'] = []

        # Parse top level acls
        for nw_address in self.portdb['acls']:
            if nw_address not in self.acldb:
                self.acldb[nw_address] = []
            for acl in self.portdb['acls'][nw_address]:
                acl = ACL(acl['match'], acl['action'])
                self.logger.info("adding %s on nw_dst:%s" % (acl, nw_address))
                self.acldb[nw_address].append(acl)

        # Parse configuration
        for port in self.portdb:
            if port in ('all', 'default', 'acls'):
                # Skip nodes that aren't real ports
                continue

            # Handle acls, default acls < port acls < global acls

            # Copy out port acls and clear port acl list
            port_acls = []
            if 'acls' in self.portdb[port]:
                port_acls = self.portdb[port]['acls']
            self.portdb[port]['acls'] = []

            # Add default acls
            if 'default' in self.portdb and \
            'acls' in self.portdb['default'] and \
            port not in self.portdb['default']['exclude']:
                self.add_acls_to_port(port, self.portdb['default']['acls'])

            # Add port acls
            self.add_acls_to_port(port, port_acls)

            # Add global acls
            if 'all' in self.portdb and 'acls' in self.portdb['all']:
                self.add_acls_to_port(port, self.portdb['all']['acls'])

            # Now that we've resolved all acls we can print them
            for acl in self.portdb[port]['acls']:
                self.logger.info("adding %s on port:%s" % (acl, port))

            # Handle vlans

            # If we have global vlans add them
            if 'all' in self.portdb and \
            all (k in self.portdb['all'] for k in ('vlans','type')):
                vlans = self.portdb['all']['vlans']
                ptype = self.portdb['all']['type']
                self.portdb[port]['vlans'] = vlans
                self.portdb[port]['type'] = ptype

            # Add vlans defined on this port (or add default values)
            if 'vlans' in self.portdb[port] and 'type' in self.portdb[port]:
                vlans = self.portdb[port]['vlans']
                ptype = self.portdb[port]['type']
                self.add_port_to_vlans(port, vlans, ptype)
            elif 'default' in self.portdb and \
            all (k in self.portdb['default'] for k in ('vlans','type')) and \
            port not in self.portdb['default']['exclude']:
                vlans = self.portdb['default']['vlans']
                ptype = self.portdb['default']['type']
                self.portdb[port]['vlans'] = vlans
                self.portdb[port]['type'] = ptype
                self.add_port_to_vlans(port, vlans, ptype)

        # Remove nodes that aren't real ports
        for n in ('all', 'default', 'acls'):
            if n in self.portdb:
                del self.portdb[n]

    def add_port_to_vlans(self, port, vlans, ptype):
        if type(vlans) is list:
            for vid in vlans:
               if vid not in self.vlandb:
                   self.vlandb[vid] = {'tagged': [], 'untagged': []}
               self.logger.info("adding %s vid:%s on port:%s" % (ptype, vid, port))
               self.vlandb[vid][ptype].append(port)
        else:
            if vlans not in self.vlandb:
                self.vlandb[vlans] = {'tagged': [], 'untagged': []}
            self.logger.info("adding %s vid:%s on port:%s" % (ptype, vid, port))
            self.vlandb[vlans][ptype].append(port)

    def add_acls_to_port(self, port, acls):
        for acl in acls:
            acl = ACL(acl['match'], acl['action'])
            if acl in self.portdb[port]['acls']:
                index = self.portdb[port]['acls'].index(acl)
                self.portdb[port]['acls'][index] = acl
            else:
                self.portdb[port]['acls'].append(acl)

    def clear_flows(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        mod = parser.OFPFlowMod(
            datapath=datapath, cookie=0, priority=LOWEST_PRIORITY,
            command=ofproto.OFPFC_DELETE, out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY, match=match, instructions=[])
        datapath.send_msg(mod)

    def add_flow(self, datapath, match, actions, priority):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                                                    actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath, cookie=0, priority=priority,
            command=ofproto.OFPFC_ADD, match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(igmplib.EventPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        pkt = packet.Packet(msg.data)
        ethernet_proto = pkt.get_protocols(ethernet.ethernet)[0]

        src = ethernet_proto.src
        dst = ethernet_proto.dst
        eth_type = ethernet_proto.ethertype

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # find the in_port:
        # TODO: allow this to support more than one dp
        in_port = msg.match['in_port']

        if in_port not in self.portdb:
          return

        if eth_type == 0x8100:
            vlan_proto = pkt.get_protocols(vlan.vlan)[0]
            vid = vlan_proto.vid
            if vid not in self.portdb[in_port]['vlans']:
                self.logger.warn("HAXX:RZ vlan:%d not on in_port:%d" % \
                    (vid, in_port))
                return
        else:
            vid = self.portdb[in_port]['vlans'][0]
            if self.portdb[in_port]['type'] == 'tagged':
                self.logger.warn("Untagged pkt_in on tagged port %d" % (in_port))
                return
        self.mac_to_port[dpid].setdefault(vid, {})

        self.logger.info("packet in dpid:%s src:%s dst:%s in_port:%d vid:%s",
                         dpid, src, dst, in_port, vid)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][vid][src] = in_port

        if dst in self.mac_to_port[dpid][vid]:
            # install a flow to avoid packet_in next time
            out_port = self.mac_to_port[dpid][vid][dst]
            actions = []

            if self.portdb[in_port]['type'] == 'tagged':
                match = parser.OFPMatch(
                    in_port=in_port,
                    eth_src=src,
                    eth_dst=dst,
                    vlan_vid=vid|ofproto_v1_3.OFPVID_PRESENT)
                if self.portdb[out_port]['type'] == 'untagged':
                    actions.append(parser.OFPActionPopVlan())
            if self.portdb[in_port]['type'] == 'untagged':
                match = parser.OFPMatch(
                    in_port=in_port,
                    eth_src=src,
                    eth_dst=dst)
                if self.portdb[out_port]['type'] == 'tagged':
                    actions.append(parser.OFPActionPushVlan())
                    actions.append(parser.OFPActionSetField(vlan_vid=vid))
            actions.append(parser.OFPActionOutput(out_port))

            self.add_flow(datapath, match, actions, HIGH_PRIORITY)

    @set_ev_cls(dpset.EventDP, dpset.DPSET_EV_DISPATCHER)
    def handler_datapath(self, ev):
        dp = ev.dp
        ofproto = dp.ofproto
        parser = dp.ofproto_parser

        # clear flow table
        self.clear_flows(dp)

        # add catchall drop rule
        match_all = parser.OFPMatch()
        drop_act  = []
        self.add_flow(dp, match_all, drop_act, LOWEST_PRIORITY)

        for vid, ports in self.vlandb.iteritems():
            controller_act = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]

            # generate the output actions for each port
            untagged_act = []
            tagged_act = []
            for port in ports['untagged']:
                untagged_act.append(parser.OFPActionOutput(port))
            for port in ports['tagged']:
                tagged_act.append(parser.OFPActionOutput(port))

            # send rule for matching packets arriving on tagged ports
            strip_act = [parser.OFPActionPopVlan()]
            action = copy.copy(controller_act)
            if tagged_act:
                action += tagged_act
            if untagged_act:
                action += strip_act + untagged_act
            match = parser.OFPMatch(vlan_vid=vid|ofproto_v1_3.OFPVID_PRESENT)
            self.add_flow(dp, match, action, LOW_PRIORITY)

            # send rule for each untagged port
            push_act = [
              parser.OFPActionPushVlan(),
              parser.OFPActionSetField(vlan_vid=vid)
              ]
            for port in ports['untagged']:
                match = parser.OFPMatch(in_port=port)
                action = copy.copy(controller_act)
                if untagged_act:
                    action += untagged_act
                if tagged_act:
                    action += push_act + tagged_act
                self.add_flow(dp, match, action, LOW_PRIORITY)

        for nw_address in self.acldb:
            for acl in self.acldb[nw_address]:
                if acl.action.lower() == "drop":
                    acl.match['nw_dst'] = nw_address
                    match = ofctl_v1_3.to_match(dp, acl.match)
                    self.add_flow(dp, match, drop_act, HIGHEST_PRIORITY)

        for port in self.portdb:
            for acl in self.portdb[port]['acls']:
                if acl.action.lower() == "drop":
                    acl.match['in_port'] = port
                    match = ofctl_v1_3.to_match(dp, acl.match)
                    self.add_flow(dp, match, drop_act, HIGHEST_PRIORITY)

        self.logger.info("valve running")

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
