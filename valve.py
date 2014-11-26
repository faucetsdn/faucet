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

import sys, struct, yaml, copy, logging, socket

import util
from acl import ACL
from dp import DP
from port import Port

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller import dpset
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3, ether
from ryu.lib import ofctl_v1_3
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

    def __init__(self, *args, **kwargs):
        super(Valve, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

        # Setup logging
        self.logger_handler = logging.StreamHandler()
        log_fmt = '%(asctime)s %(name)-6s %(levelname)-8s %(message)s'
        formatter = logging.Formatter(log_fmt, '%b %d %H:%M:%S')
        self.logger_handler.setFormatter(formatter)
        self.logger.addHandler(self.logger_handler)
        self.logger.propagate = 0

        self.dps = {}

        # Read in config file
        with open('valve.yaml', 'r') as stream:
            self.conf = yaml.load(stream)

            # Convert all acls to ACL objects
            self.fix_acls(self.conf)

            for dpid, dpconfig in self.conf.items():
                if dpid in ('all', 'default', 'acls'):
                    continue

                conf_all = [ copy.deepcopy(self.conf['all']) ] if 'all' in self.conf else [{}]
                conf_def = copy.deepcopy(self.conf['default']) if 'default' in self.conf else {}
                conf_acls = copy.deepcopy(self.conf['acls']) if 'acls' in self.conf else {}

                # Merge dpconfig['all'] into conf_all
                if 'all' in dpconfig:
                    conf_all.append(dpconfig['all'])

                    del dpconfig['all']

                # Merge dpconfig['default'] into conf_def
                if 'default' in dpconfig:
                    if 'vlans' in dpconfig['default']:
                        # Let DP-default vlan config
                        # override global-default vlan config
                        conf_def['vlans'] = dpconfig['default']['vlans']

                    if 'type' in dpconfig['default']:
                        # Let DP-default type config
                        # override global-default type config
                        conf_def['type'] = dpconfig['default']['type']

                    if 'acls' in dpconfig['default']:
                        # Let DP-default acl config
                        # override global-default acl config
                        conf_def['acls'] = dpconfig['default']['acls']

                    if 'exclude' in dpconfig['default']:
                        # Let DP-default exclude config
                        # override global-default exclude config
                        conf_def['exclude'] = dpconfig['default']['exclude']

                    del dpconfig['default']

                # Merge dpconfig['acls'] into conf_acls
                if 'acls' in dpconfig:
                    for ip, acls in dpconfig['acls'].items():
                        conf_acls.setdefault(ip, [])
                        conf_acls[ip].extend(x for x in acls if x not in conf_acls[ip])

                    del dpconfig['acls']

                # Add datapath
                self.dps[dpid] = DP(dpid, dpconfig, conf_all, conf_def, conf_acls)

    def fix_acls(self, conf):
        # Recursively walk config replacing all acls with ACL objects
        for k, v in conf.items():
            if k == 'acls':
                if isinstance(v, dict):
                    for ip, acls in v.items():
                        conf[k][ip] = [ACL(x['match'], x['action']) for x in acls]
                else:
                    conf[k] = [ACL(x['match'], x['action']) for x in v]
            elif isinstance(v, dict):
                self.fix_acls(v)

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

    def tagged_output_action(self, parser, tagged_ports):
        act = []
        for port in tagged_ports:
            act.append(parser.OFPActionOutput(port.number))
        return act

    def untagged_output_action(self, parser, untagged_ports):
        act = []
        for port in untagged_ports:
            act.append(parser.OFPActionOutput(port.number))
        return act

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofproto = dp.ofproto
        parser = dp.ofproto_parser

        pkt = packet.Packet(msg.data)
        ethernet_proto = pkt.get_protocols(ethernet.ethernet)[0]

        src = ethernet_proto.src
        dst = ethernet_proto.dst
        eth_type = ethernet_proto.ethertype

        in_port = msg.match['in_port']
        self.mac_to_port.setdefault(dp.id, {})

        # Configure logging to include datapath id
        dp_str = 'dpid:%-16x' % dp.id
        log_fmt = '%(asctime)s %(name)-6s %(levelname)-8s '+dp_str+' %(message)s'
        formatter = logging.Formatter(log_fmt, '%b %d %H:%M:%S')
        self.logger_handler.setFormatter(formatter)

        if dp.id not in self.dps:
            self.logger.error("Packet_in on unknown datapath")
            return
        else:
            datapath = self.dps[dp.id]

        if not datapath.running:
            self.logger.error("Packet_in on unconfigured datapath")

        if in_port not in datapath.ports:
            return

        if eth_type == ether.ETH_TYPE_8021Q:
            # tagged packet
            vlan_proto = pkt.get_protocols(vlan.vlan)[0]
            vid = vlan_proto.vid
            if Port(in_port, 'tagged') not in datapath.vlans[vid].tagged:
                self.logger.warn("HAXX:RZ in_port:%d isn't tagged on vid:%s" % \
                    (in_port, vid))
                return
        else:
            # untagged packet
            vid = datapath.get_native_vlan(in_port).vid
            if not vid:
                self.logger.warn("Untagged packet_in on port:%d without native vlan" % \
                        (in_port))
                return

        self.mac_to_port[dp.id].setdefault(vid, {})

        self.logger.info("Packet_in src:%s dst:%s in_port:%d vid:%s",
                         src, dst, in_port, vid)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dp.id][vid][src] = in_port

        # generate the output actions for broadcast traffic
        tagged_act = self.tagged_output_action(parser, datapath.vlans[vid].tagged)
        untagged_act = self.untagged_output_action(parser, datapath.vlans[vid].untagged)

        matches = []
        action = []
        if datapath.ports[in_port].is_tagged():
            # send rule for mathcing packets arriving on tagged ports
            strip_act = [parser.OFPActionPopVlan()]
            if tagged_act:
                action += tagged_act
            if untagged_act:
                action += strip_act + untagged_act

            matches.append(parser.OFPMatch(vlan_vid=vid|ofproto_v1_3.OFPVID_PRESENT,
                    in_port=in_port, eth_src=src, eth_dst='ff:ff:ff:ff:ff:ff'))

            matches.append(parser.OFPMatch(vlan_vid=vid|ofproto_v1_3.OFPVID_PRESENT,
                    in_port=in_port,
                    eth_src=src,
                    eth_dst=('01:00:00:00:00:00',
                             '01:00:00:00:00:00')))
        elif datapath.ports[in_port].is_untagged():
            # send rule for each untagged port
            push_act = [
              parser.OFPActionPushVlan(ether.ETH_TYPE_8021Q),
              parser.OFPActionSetField(vlan_vid=vid|ofproto_v1_3.OFPVID_PRESENT)
              ]
            if untagged_act:
                action += untagged_act
            if tagged_act:
                action += push_act + tagged_act

            matches.append(parser.OFPMatch(in_port=in_port, eth_src=src,
                    eth_dst='ff:ff:ff:ff:ff:ff'))

            matches.append(parser.OFPMatch(in_port=in_port,
                    eth_src=src,
                    eth_dst=('01:00:00:00:00:00',
                             '01:00:00:00:00:00')))

        # install broadcast flows onto datapath
        for match in matches:
            self.add_flow(dp, match, action, LOW_PRIORITY)

        # install unicast flows onto datapath
        if dst in self.mac_to_port[dp.id][vid]:
            self.logger.info("Adding unicast flow dl_dst:%s vid:%d", dst, vid)

            # install a flow to avoid packet_in next time
            out_port = self.mac_to_port[dp.id][vid][dst]
            actions = []

            if datapath.ports[in_port].is_tagged():
                match = parser.OFPMatch(
                    in_port=in_port,
                    eth_src=src,
                    eth_dst=dst,
                    vlan_vid=vid|ofproto_v1_3.OFPVID_PRESENT)
                if datapath.ports[out_port].is_untagged():
                    actions.append(parser.OFPActionPopVlan())
            if datapath.ports[in_port].is_untagged():
                match = parser.OFPMatch(
                    in_port=in_port,
                    eth_src=src,
                    eth_dst=dst)
                if datapath.ports[out_port].is_tagged():
                    actions.append(parser.OFPActionPushVlan())
                    actions.append(parser.OFPActionSetField(vlan_vid=vid|ofproto_v1_3.OFPVID_PRESENT))
            actions.append(parser.OFPActionOutput(out_port))

            self.add_flow(dp, match, actions, HIGH_PRIORITY)

    @set_ev_cls(dpset.EventDP, dpset.DPSET_EV_DISPATCHER)
    def handler_datapath(self, ev):
        dp = ev.dp
        ofproto = dp.ofproto
        parser = dp.ofproto_parser

        # Configure logging to include datapath id
        dp_str = 'dpid:%-16x' % dp.id
        log_fmt = '%(asctime)s %(name)-6s %(levelname)-8s '+dp_str+' %(message)s'
        formatter = logging.Formatter(log_fmt, '%b %d %H:%M:%S')
        self.logger_handler.setFormatter(formatter)

        if dp.id not in self.dps:
            self.logger.error("Unknown dpid:%s", dp.id)
            return
        else:
            datapath = self.dps[dp.id]

        for k, port in dp.ports.items():
            # These are special port numbers
            if k > 0xF0000000:
                continue
            elif k not in datapath.ports:
                # Autoconfigure port
                self.logger.info("Autoconfiguring port:%s based on default config",
                        k)
                datapath.add_port(k)

        self.logger.info("Configuring datapath")

        # clear flow table on datapath
        self.clear_flows(dp)

        # add catchall drop rule to datapath
        match_all = parser.OFPMatch()
        drop_act  = []
        self.add_flow(dp, match_all, drop_act, LOWEST_PRIORITY)

        for vid, v in datapath.vlans.items():
            self.logger.info("Configuring %s", v)

            controller_act = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]

            # generate the output actions for each port
            tagged_act = self.tagged_output_action(parser, v.tagged)
            untagged_act = self.untagged_output_action(parser, v.untagged)

            # send rule for matching packets arriving on tagged ports
            strip_act = [parser.OFPActionPopVlan()]
            action = copy.copy(controller_act)
            if tagged_act:
                action += tagged_act
            if untagged_act:
                action += strip_act + untagged_act
            match = parser.OFPMatch(vlan_vid=v.vid|ofproto_v1_3.OFPVID_PRESENT)
            self.add_flow(dp, match, action, LOW_PRIORITY)

            # send rule for each untagged port
            push_act = [
              parser.OFPActionPushVlan(ether.ETH_TYPE_8021Q),
              parser.OFPActionSetField(vlan_vid=v.vid|ofproto_v1_3.OFPVID_PRESENT)
              ]

            for port in v.untagged:
                match = parser.OFPMatch(in_port=port.number)
                action = copy.copy(controller_act)
                if untagged_act:
                    action += untagged_act
                if tagged_act:
                    action += push_act + tagged_act
                self.add_flow(dp, match, action, LOW_PRIORITY)

        for nw_address, acls in datapath.acls.items():
            for acl in acls:
                if acl.action.lower() == "drop":
                    self.logger.info("Adding ACL:{%s} for nw_address:%s",
                            acl, nw_address)

                    # Hacky method of detecting IPv4/IPv6
                    try:
                        socket.inet_aton(nw_address.split('/')[0])
                        acl.match['nw_dst'] = nw_address
                    except socket.error:
                        acl.match['ipv6_dst'] = nw_address

                    match = ofctl_v1_3.to_match(dp, acl.match)
                    self.add_flow(dp, match, drop_act, HIGHEST_PRIORITY)

        for k, port in datapath.ports.items():
            for acl in port.acls:
                if acl.action.lower() == "drop":
                    self.logger.info("Adding ACL:{%s} to port:%s", acl, port)
                    acl.match['in_port'] = port.number
                    match = ofctl_v1_3.to_match(dp, acl.match)
                    self.add_flow(dp, match, drop_act, HIGHEST_PRIORITY)

        # Mark datapath as fully configured
        datapath.running = True

        self.logger.info("Datapath configured")
