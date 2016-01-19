# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2015 Brad Cowie, Christopher Lorier and Joe Stringer.
# Copyright (C) 2015 Research and Innovation Advanced Network New Zealand Ltd.
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
from ryu.ofproto import ofproto_v1_3, ether
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import vlan


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
            'FAUCET_CONFIG', '/etc/ryu/faucet/faucet.yaml')
        self.logfile = os.getenv('FAUCET_LOG_DIR', '/var/log/ryu/') + 'faucet.log'
        self.exc_logfile = os.getenv(
            'FAUCET_LOG_DIR', '/var/log/ryu/') + 'faucet_exception.log'

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

        # Parse config file
        dp = DP.parser(self.config_file, self.logname)

        if dp:
            try:
                dp.sanity_check()
            except AssertionError:
                self.logger.exception("Error in config file:")

            # Load Valve
            self.valve = valve_factory(dp)
            if self.valve is None:
                self.logger.error("Hardware type not supported")

    def signal_handler(self, sigid, frame):
        if sigid == signal.SIGHUP:
            self.logger.info("Caught SIGHUP, reloading configuration")

            new_config_file = os.getenv('FAUCET_CONFIG', self.config_file)

            new_dp = DP.parser(new_config_file, self.logname)

            if new_dp:
                try:
                    new_dp.sanity_check()
                except AssertionError:
                    self.logger.exception("Error in config file:")

                flowmods = self.valve.reload_config(new_dp)
                ryudp = self.dpset.get(new_dp.dp_id)
                for f in flowmods:
                    # OpenFlow Message objects in ryu require a ryu datapath
                    # object
                    f.datapath = ryudp
                    ryudp.send_msg(f)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    @kill_on_exception(exc_logname)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath

        pkt = packet.Packet(msg.data)
        ethernet_proto = pkt.get_protocols(ethernet.ethernet)[0]

        src = ethernet_proto.src
        dst = ethernet_proto.dst
        eth_type = ethernet_proto.ethertype

        in_port = msg.match['in_port']

        if eth_type == ether.ETH_TYPE_8021Q:
            # tagged packet
            vlan_proto = pkt.get_protocols(vlan.vlan)[0]
            vlan_vid = vlan_proto.vid
        else:
            return

        flowmods = self.valve.rcv_packet(dp.id, in_port, vlan_vid, src, dst)
        for f in flowmods:
            # OpenFlow Message objects in ryu require a ryu datapath object
            f.datapath = dp
            dp.send_msg(f)

    @set_ev_cls(dpset.EventDP, dpset.DPSET_EV_DISPATCHER)
    @kill_on_exception(exc_logname)
    def handler_datapath(self, ev):
        dp = ev.dp

        if not ev.enter:
            # Datapath down message
            self.valve.datapath_disconnect(dp.id)
            return

        ports = [p.port_no for p in dp.ports.values() if p.state == 0]
        flowmods = self.valve.datapath_connect(dp.id, ports)
        for f in flowmods:
            # OpenFlow Message objects in ryu require a ryu datapath object
            f.datapath = dp
            dp.send_msg(f)

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    @kill_on_exception(exc_logname)
    def port_status_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        reason = msg.reason
        port_no = msg.desc.port_no
        ofp = msg.datapath.ofproto
        flowmods = []
        if reason == ofp.OFPPR_ADD:
            flowmods = self.valve.port_add(dp.id, port_no)
        elif reason == ofp.OFPPR_DELETE:
            flowmods = self.valve.port_delete(dp.id, port_no)
        elif reason == ofp.OFPPR_MODIFY\
        and (msg.desc.state & ofp.OFPPS_LINK_DOWN):
            flowmods = self.valve.port_delete(dp.id, port_no)
        elif reason == ofp.OFPPR_MODIFY\
        and not (msg.desc.state & ofp.OFPPS_LINK_DOWN):
            flowmods = self.valve.port_add(dp.id, port_no)
        else:
            self.logger.info("Illegal port state %s %s", port_no, reason)
        for f in flowmods:
            # OpenFlow Message objects in ryu require a ryu datapath object
            f.datapath = dp
            dp.send_msg(f)
