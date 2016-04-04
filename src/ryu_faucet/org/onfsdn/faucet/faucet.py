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
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os, signal, logging

from logging.handlers import TimedRotatingFileHandler

from valve import valve_factory
from util import kill_on_exception
from dp import DP

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller import dpset
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.controller import event
from ryu.ofproto import ofproto_v1_3, ether
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import vlan
from ryu.lib import hub


class EventFaucetReconfigure(event.EventBase):
    pass


class EventFaucetResolveGateways(event.EventBase):
    pass


class Faucet(app_manager.RyuApp):
    """A Ryu app that performs layer 2 switching with VLANs.

    The intelligence is largely provided by a Valve class. Faucet's role is
    mainly to perform set up and to provide a communication layer between ryu
    and valve.
    """
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    _CONTEXTS = {'dpset': dpset.DPSet}

    logname = 'faucet'
    exc_logname = logname + '.exception'

    def __init__(self, *args, **kwargs):
        super(Faucet, self).__init__(*args, **kwargs)

        # There doesnt seem to be a sensible method of getting command line
        # options into ryu apps. Instead I am using the environment variable
        # FAUCET_CONFIG to allow this to be set, if it is not set it will
        # default to valve.yaml
        self.config_file = os.getenv(
            'FAUCET_CONFIG', '/etc/opt/faucet/valve.yaml')
        self.logfile = os.getenv(
            'FAUCET_LOG', '/var/log/faucet/faucet.log')
        self.exc_logfile = os.getenv(
            'FAUCET_EXCEPTION_LOG', '/var/log/faucet/faucet_exception.log')

        # Set the signal handler for reloading config file
        signal.signal(signal.SIGHUP, self.signal_handler)

        # Create dpset object for querying Ryu's DPSet application
        self.dpset = kwargs['dpset']

        # Setup logging
        self.logger = logging.getLogger(self.logname)
        logger_handler = TimedRotatingFileHandler(
            self.logfile,
            when='midnight')
        log_fmt = '%(asctime)s %(name)-6s %(levelname)-8s %(message)s'
        logger_handler.setFormatter(
            logging.Formatter(log_fmt, '%b %d %H:%M:%S'))
        self.logger.addHandler(logger_handler)
        self.logger.propagate = 0
        self.logger.setLevel(logging.DEBUG)

        # Set up separate logging for exceptions
        exc_logger = logging.getLogger(self.exc_logname)
        exc_logger_handler = logging.FileHandler(self.exc_logfile)
        exc_logger_handler.setFormatter(
            logging.Formatter(log_fmt, '%b %d %H:%M:%S'))
        exc_logger.addHandler(exc_logger_handler)
        exc_logger.propagate = 1
        exc_logger.setLevel(logging.CRITICAL)

        dp = self.parse_config(self.config_file, self.logname)
        self.valve = valve_factory(dp)
        if self.valve is None:
            self.logger.error("Hardware type not supported")

        self.gateway_resolve_request_thread = hub.spawn(
            self.gateway_resolve_request)


    def gateway_resolve_request(self):
        while True:
            self.send_event('Faucet', EventFaucetResolveGateways())
            hub.sleep(2)

    def parse_config(self, config_file, log_name):
        new_dp = DP.parser(config_file, log_name)
        if new_dp:
            try:
                new_dp.sanity_check()
                return new_dp
            except AssertionError:
                self.logger.exception("Error in config file:")
        return None

    def send_flow_msgs(self, dp, flow_msgs):
        for flow_msg in flow_msgs:
            flow_msg.datapath = dp
            dp.send_msg(flow_msg)

    def signal_handler(self, sigid, frame):
        if sigid == signal.SIGHUP:
            self.send_event('Faucet', EventFaucetReconfigure())

    @set_ev_cls(EventFaucetReconfigure, MAIN_DISPATCHER)
    def reload_config(self, ev):
        new_config_file = os.getenv('FAUCET_CONFIG', self.config_file)
        new_dp = self.parse_config(new_config_file, self.logname)
        if new_dp:
            flowmods = self.valve.reload_config(new_dp)
            ryudp = self.dpset.get(new_dp.dp_id)
            self.send_flow_msgs(ryudp, flowmods)

    @set_ev_cls(EventFaucetResolveGateways, MAIN_DISPATCHER)
    def resolve_gateways(self, ev):
        if self.valve is not None:
            flowmods = self.valve.resolve_gateways()
            if flowmods:
                ryudp = self.dpset.get(self.valve.dp.dp_id)
                self.send_flow_msgs(ryudp, flowmods)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    @kill_on_exception(exc_logname)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath

        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocols(ethernet.ethernet)[0]
        eth_type = eth_pkt.ethertype

        if eth_type == ether.ETH_TYPE_8021Q:
            # tagged packet
            vlan_proto = pkt.get_protocols(vlan.vlan)[0]
            vlan_vid = vlan_proto.vid
        else:
            return
        
        in_port = msg.match['in_port']
        flowmods = self.valve.rcv_packet(dp.id, in_port, vlan_vid, msg.match, pkt)
        self.send_flow_msgs(dp, flowmods)
        


        ip_hdr = pkt.get_protocols(ipv4.ipv4)
        

        if len(ip_hdr)!=0:
            src_ip = ip_hdr[0].src
            dst_ip = ip_hdr[0].dst
            self.logger.info("ipv4 src %s, dst %s", src_ip, dst_ip)
            netflix_src_list = tuple(open('./Netflix_AS2906', 'r'))
            if src_ip in netflix_src_list:
                tcp_hdr = pkt.get_protocols(tcp.tcp)
                if len(tcp_hdr)!=0:
                    src_port = tcp_hdr[0].src_port
                    dst_port = tcp_hdr[0].dst_port
                    self.logger.info("tcp src_port %s, dst_port %s", src_port,dst_port)
                    self.logger.info("inserting this particular flow entry: %s:%s %s:%s", src_ip,src_port,dst_ip,dst_port)
                    flowmods = self.valve.netflix_flows_insertion(ev)        

        # if ip_src in netflix_src_list :
        #     src_ip = msg.match['src_ip']
        #     dst_ip = msg.match['dst_ip']
        #     in_port = msg.match['in_port']
        #     flowmods = self.valve.rcv_packet(dp.id, in_port, vlan_vid, msg.match, pkt)




    @set_ev_cls(dpset.EventDP, dpset.DPSET_EV_DISPATCHER)
    @kill_on_exception(exc_logname)
    def handler_datapath(self, ev):
        dp = ev.dp

        if not ev.enter:
            # Datapath down message
            self.valve.datapath_disconnect(dp.id)
            return

        discovered_ports = [
            p.port_no for p in dp.ports.values() if p.state == 0]
        flowmods = self.valve.datapath_connect(dp.id, discovered_ports)
        self.logger.info("before send flowmods")
        self.send_flow_msgs(dp, flowmods)
        self.logger.info("before opening netflix file")
        netflix_src_list = tuple(open('./Netflix_AS2906', 'r'))
        
        for netflix_src in netflix_src_list:
            self.logger.info("initiating and inserting netflix src flow entry: %s", netflix_src)
            flowmods = self.valve.netflix_flows_initiation(dp, netflix_src)
            self.logger.info("after creating flowmods")
            dp.send_msg(flowmods)

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    @kill_on_exception(exc_logname)
    def port_status_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = msg.datapath.ofproto
        reason = msg.reason
        port_no = msg.desc.port_no

        flowmods = []
        if reason == ofp.OFPPR_ADD:
            flowmods = self.valve.port_add(dp.id, port_no)
        elif reason == ofp.OFPPR_DELETE:
            flowmods = self.valve.port_delete(dp.id, port_no)
        elif reason == ofp.OFPPR_MODIFY:
            port_down = msg.desc.state & ofp.OFPPS_LINK_DOWN
            if port_down:
                flowmods = self.valve.port_delete(dp.id, port_no)
            else:
                flowmods = self.valve.port_add(dp.id, port_no)
        else:
            self.logger.info('Unhandled port status %s for port %u',
                             reason, port_no)

        self.send_flow_msgs(dp, flowmods)
