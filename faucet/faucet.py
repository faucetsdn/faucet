"""RyuApp shim between Ryu and Valve."""

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
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
import os
import random
import signal

from config_parser import dp_parser, get_config_for_api
from config_parser_util import config_changed
from valve_util import dpid_log, get_logger, kill_on_exception, get_sys_prefix
from valve import valve_factory
import faucet_api
import faucet_bgp
import faucet_metrics
import valve_packet
import valve_of

from ryu.base import app_manager
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.controller import dpset
from ryu.controller import event
from ryu.controller import ofp_event
from ryu.lib import hub


class EventFaucetReconfigure(event.EventBase):
    """Event used to trigger FAUCET reconfiguration."""
    pass


class EventFaucetResolveGateways(event.EventBase):
    """Event used to trigger gateway re/resolution."""
    pass


class EventFaucetHostExpire(event.EventBase):
    """Event used to trigger expiration of host state in controller."""
    pass


class EventFaucetMetricUpdate(event.EventBase):
    """Event used to trigger update of metrics."""
    pass


class EventFaucetAdvertise(event.EventBase):
    """Event used to trigger periodic network advertisements (eg IPv6 RAs)."""
    pass


class EventFaucetAPIRegistered(event.EventBase):
    """Event used to notify that the API is registered with Faucet."""
    pass


class Faucet(app_manager.RyuApp):
    """A RyuApp that implements an L2/L3 learning VLAN switch.

    Valve provides the switch implementation; this is a shim for the Ryu
    event handling framework to interface with Valve.
    """
    OFP_VERSIONS = valve_of.OFP_VERSIONS
    _CONTEXTS = {
        'dpset': dpset.DPSet,
        'faucet_api': faucet_api.FaucetAPI
        }
    logname = 'faucet'
    exc_logname = logname + '.exception'

    def __init__(self, *args, **kwargs):
        super(Faucet, self).__init__(*args, **kwargs)

        # There doesnt seem to be a sensible method of getting command line
        # options into ryu apps. Instead I am using the environment variable
        # FAUCET_CONFIG to allow this to be set, if it is not set it will
        # default to valve.yaml
        sysprefix = get_sys_prefix()
        self.config_file = os.getenv(
            'FAUCET_CONFIG', sysprefix + '/etc/ryu/faucet/faucet.yaml')
        self.logfile = os.getenv(
            'FAUCET_LOG', sysprefix + '/var/log/ryu/faucet/faucet.log')
        self.exc_logfile = os.getenv(
            'FAUCET_EXCEPTION_LOG',
            sysprefix + '/var/log/ryu/faucet/faucet_exception.log')

        # Create dpset object for querying Ryu's DPSet application
        self.dpset = kwargs['dpset']

        # Setup logging
        self.logger = get_logger(
            self.logname, self.logfile, logging.DEBUG, 0)
        # Set up separate logging for exceptions
        self.exc_logger = get_logger(
            self.exc_logname, self.exc_logfile, logging.DEBUG, 1)

        self.valves = {}

        # Start Prometheus
        prom_port = int(os.getenv('FAUCET_PROMETHEUS_PORT', '9244'))
        prom_addr = os.getenv('FAUCET_PROMETHEUS_ADDR', '')
        self.metrics = faucet_metrics.FaucetMetrics(
            prom_port, prom_addr)

        # Start BGP
        self._bgp = faucet_bgp.FaucetBgp(self.logger, self._send_flow_msgs)

        # Configure all Valves
        self._load_configs(self.config_file)

        # Start all threads
        self._threads = [
            hub.spawn(thread) for thread in (
                self._gateway_resolve_request, self._host_expire_request,
                self._metric_update_request, self._advertise_request)]

        # Register to API
        api = kwargs['faucet_api']
        api._register(self)
        self.send_event_to_observers(EventFaucetAPIRegistered())

        # Set the signal handler for reloading config file
        signal.signal(signal.SIGHUP, self._signal_handler)

    @kill_on_exception(exc_logname)
    def _load_configs(self, new_config_file):
        self.config_file = new_config_file
        self.config_hashes, new_dps = dp_parser(
            new_config_file, self.logname)
        deleted_valve_dpids = (
            set(list(self.valves.keys())) -
            set([valve.dp_id for valve in new_dps]))
        for new_dp in new_dps:
            dp_id = new_dp.dp_id
            if dp_id in self.valves:
                valve = self.valves[dp_id]
                cold_start, flowmods = valve.reload_config(new_dp)
                # pylint: disable=no-member
                if flowmods:
                    self._send_flow_msgs(new_dp.dp_id, flowmods)
                    if cold_start:
                        self.metrics.faucet_config_reload_cold.labels(
                            dpid=hex(dp_id)).inc()
                    else:
                        self.metrics.faucet_config_reload_warm.labels(
                            dpid=hex(dp_id)).inc()
            else:
                # pylint: disable=no-member
                valve_cl = valve_factory(new_dp)
                if valve_cl is None:
                    self.logger.fatal('Could not configure %s', new_dp.name)
                else:
                    valve = valve_cl(new_dp, self.logname)
                    self.valves[dp_id] = valve
                self.logger.info('Add new datapath %s', dpid_log(dp_id))
            valve.update_config_metrics(self.metrics)
        for deleted_valve_dpid in deleted_valve_dpids:
            self.logger.info(
                'Deleting de-configured %s', dpid_log(deleted_valve_dpid))
            del self.valves[deleted_valve_dpid]
            ryu_dp = self.dpset.get(deleted_valve_dpid)
            if ryu_dp is not None:
                ryu_dp.close()
        self._bgp.reset(self.valves, self.metrics)

    @kill_on_exception(exc_logname)
    def _send_flow_msgs(self, dp_id, flow_msgs, ryu_dp=None):
        """Send OpenFlow messages to a connected datapath.

        Args:
            dp_id (int): datapath ID.
            flow_msgs (list): OpenFlow messages to send.
            ryu_dp: Override datapath from DPSet.
        """
        if ryu_dp is None:
            ryu_dp = self.dpset.get(dp_id)
            if not ryu_dp:
                self.logger.error('send_flow_msgs: %s not up', dpid_log(dp_id))
                return
            if dp_id not in self.valves:
                self.logger.error('send_flow_msgs: unknown %s', dpid_log(dp_id))
                return

        valve = self.valves[dp_id]
        reordered_flow_msgs = valve.valve_flowreorder(flow_msgs)
        valve.ofchannel_log(reordered_flow_msgs)
        for flow_msg in reordered_flow_msgs:
            # pylint: disable=no-member
            self.metrics.of_flowmsgs_sent.labels(
                dpid=hex(dp_id)).inc()
            flow_msg.datapath = ryu_dp
            ryu_dp.send_msg(flow_msg)

    def _signal_handler(self, sigid, _):
        """Handle any received signals.

        Args:
            sigid (int): signal to handle.
        """
        if sigid == signal.SIGHUP:
            self.send_event('Faucet', EventFaucetReconfigure())

    def _thread_reschedule(self, ryu_event, period, jitter=2):
        """Trigger Ryu events periodically with a jitter.

        Args:
            ryu_event (ryu.controller.event.EventReplyBase): event to trigger.
            period (int): how often to trigger.
        """
        while True:
            self.send_event('Faucet', ryu_event)
            hub.sleep(period + random.randint(0, jitter))

    def _gateway_resolve_request(self):
        self._thread_reschedule(EventFaucetResolveGateways(), 2)

    def _host_expire_request(self):
        self._thread_reschedule(EventFaucetHostExpire(), 5)

    def _metric_update_request(self):
        self._thread_reschedule(EventFaucetMetricUpdate(), 5)

    def _advertise_request(self):
        self._thread_reschedule(EventFaucetAdvertise(), 5)

    @set_ev_cls(EventFaucetResolveGateways, MAIN_DISPATCHER)
    @kill_on_exception(exc_logname)
    def resolve_gateways(self, _):
        """Handle a request to re/resolve gateways."""
        for dp_id, valve in list(self.valves.items()):
            flowmods = valve.resolve_gateways()
            if flowmods:
                self._send_flow_msgs(dp_id, flowmods)

    @set_ev_cls(EventFaucetHostExpire, MAIN_DISPATCHER)
    @kill_on_exception(exc_logname)
    def host_expire(self, _):
        """Handle a request expire host state in the controller."""
        for valve in list(self.valves.values()):
            valve.host_expire()
            valve.update_metrics(self.metrics)

    @set_ev_cls(EventFaucetMetricUpdate, MAIN_DISPATCHER)
    @kill_on_exception(exc_logname)
    def metric_update(self, _):
        """Handle a request to update metrics in the controller."""
        self._bgp.update_metrics()

    @set_ev_cls(EventFaucetAdvertise, MAIN_DISPATCHER)
    @kill_on_exception(exc_logname)
    def advertise(self, _):
        """Handle a request to advertise services."""
        for dp_id, valve in list(self.valves.items()):
            flowmods = valve.advertise()
            if flowmods:
                self._send_flow_msgs(dp_id, flowmods)

    @set_ev_cls(EventFaucetReconfigure, MAIN_DISPATCHER)
    def reload_config(self, _):
        """Handle a request to reload configuration."""
        self.logger.info('request to reload configuration')
        new_config_file = os.getenv('FAUCET_CONFIG', self.config_file)
        if config_changed(self.config_file, new_config_file, self.config_hashes):
            self.logger.info('configuration changed')
            self._load_configs(new_config_file)
        else:
            self.logger.info('configuration is unchanged, not reloading')
        # pylint: disable=no-member
        self.metrics.faucet_config_reload_requests.inc()

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER) # pylint: disable=no-member
    @kill_on_exception(exc_logname)
    def _packet_in_handler(self, ryu_event):
        """Handle a packet in event from the dataplane.

        Args:
            ryu_event (ryu.controller.event.EventReplyBase): packet in message.
        """
        msg = ryu_event.msg
        ryu_dp = msg.datapath
        dp_id = ryu_dp.id

        if not dp_id in self.valves:
            self.logger.error('_packet_in_handler: unknown %s', dpid_log(dp_id))
            return

        valve = self.valves[dp_id]
        valve.ofchannel_log([msg])

        pkt, vlan_vid = valve_packet.parse_packet_in_pkt(msg)
        if pkt is None or vlan_vid is None:
            return

        in_port = msg.match['in_port']
        # pylint: disable=no-member
        self.metrics.of_packet_ins.labels(
            dpid=hex(dp_id)).inc()
        flowmods = valve.rcv_packet(
            dp_id, self.valves, in_port, vlan_vid, pkt)
        self._send_flow_msgs(dp_id, flowmods)
        valve.update_metrics(self.metrics)

    @set_ev_cls(ofp_event.EventOFPErrorMsg, MAIN_DISPATCHER) # pylint: disable=no-member
    @kill_on_exception(exc_logname)
    def _error_handler(self, ryu_event):
        """Handle an OFPError from a datapath.

        Args:
            ryu_event (ryu.controller.ofp_event.EventOFPErrorMsg): trigger
        """
        msg = ryu_event.msg
        ryu_dp = msg.datapath
        dp_id = ryu_dp.id
        if dp_id in self.valves:
            # pylint: disable=no-member
            self.metrics.of_errors.labels(
                dpid=hex(dp_id)).inc()
            self.valves[dp_id].ofchannel_log([msg])
        self.logger.error('OFError %s from %s', msg, dpid_log(dp_id))

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER) # pylint: disable=no-member
    @kill_on_exception(exc_logname)
    def handler_features(self, ryu_event):
        """Handle receiving a switch features message from a datapath.

        Args:
            ryu_event (ryu.controller.ofp_event.EventOFPStateChange): trigger.
        """
        msg = ryu_event.msg
        ryu_dp = msg.datapath
        dp_id = ryu_dp.id
        if dp_id in self.valves:
            valve = self.valves[dp_id]
            flowmods = valve.switch_features(dp_id, msg)
            self._send_flow_msgs(dp_id, flowmods, ryu_dp=ryu_dp)
        else:
            self.logger.error('handler_features: unknown %s', dpid_log(dp_id))
            ryu_dp.close()

    @kill_on_exception(exc_logname)
    def _handler_datapath(self, ryu_dp):
        """Handle any/all re/dis/connection of a datapath.

        Args:
            ryu_dp (ryu.controller.controller.Datapath): datapath.
        """
        dp_id = ryu_dp.id
        if dp_id in self.valves:
            discovered_up_port_nums = [
                port.port_no for port in list(ryu_dp.ports.values()) if port.state == 0]
            valve = self.valves[dp_id]
            flowmods = valve.datapath_connect(
                dp_id, discovered_up_port_nums)
            self._send_flow_msgs(dp_id, flowmods)
        else:
            self.logger.error('handler_datapath: unknown %s', dpid_log(dp_id))
            ryu_dp.close()

    @set_ev_cls(dpset.EventDP, dpset.DPSET_EV_DISPATCHER)
    @kill_on_exception(exc_logname)
    def handler_connect_or_disconnect(self, ryu_event):
        """Handle connection or disconnection of a datapath.

        Args:
            ryu_event (ryu.controller.dpset.EventDP): trigger.
        """
        ryu_dp = ryu_event.dp
        dp_id = ryu_dp.id
        if dp_id in self.valves:
            valve = self.valves[dp_id]
            # pylint: disable=no-member
            if ryu_event.enter:
                self.metrics.of_dp_connections.labels(
                    dpid=hex(dp_id)).inc()
                self.logger.debug('%s connected', dpid_log(dp_id))
                self._handler_datapath(ryu_dp)
                # pylint: disable=no-member
                self.metrics.dp_status.labels(
                    dpid=hex(dp_id)).set(1)
            else:
                self.metrics.of_dp_disconnections.labels(
                    dpid=hex(dp_id)).inc()
                # pylint: disable=no-member
                self.metrics.dp_status.labels(
                    dpid=hex(dp_id)).set(0)
                self.logger.debug('%s disconnected', dpid_log(dp_id))
                valve.datapath_disconnect(dp_id)
        else:
            self.logger.error(
                'handler_connect_or_disconnect: unknown %s', dpid_log(dp_id))
            ryu_dp.close()

    @set_ev_cls(dpset.EventDPReconnected, dpset.DPSET_EV_DISPATCHER)
    @kill_on_exception(exc_logname)
    def handler_reconnect(self, ryu_event):
        """Handle reconnection of a datapath.

        Args:
            ryu_event (ryu.controller.dpset.EventDPReconnected): trigger.
        """
        ryu_dp = ryu_event.dp
        dp_id = ryu_dp.id
        self.logger.debug('%s reconnected', dpid_log(dp_id))
        # pylint: disable=no-member
        self.metrics.dp_status.labels(
            dpid=hex(dp_id)).set(1)
        self._handler_datapath(ryu_dp)

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER) # pylint: disable=no-member
    @kill_on_exception(exc_logname)
    def port_status_handler(self, ryu_event):
        """Handle a port status change event.

        Args:
            ryu_event (ryu.controller.ofp_event.EventOFPPortStatus): trigger.
        """
        msg = ryu_event.msg
        ryu_dp = msg.datapath
        dp_id = ryu_dp.id
        ofp = msg.datapath.ofproto
        reason = msg.reason
        port_no = msg.desc.port_no
        port_down = msg.desc.state & ofp.OFPPS_LINK_DOWN
        port_status = not port_down
        if dp_id in self.valves:
            valve = self.valves[dp_id]
            flowmods = valve.port_status_handler(
                dp_id, port_no, reason, port_status)
            self._send_flow_msgs(dp_id, flowmods)
            # pylint: disable=no-member
            self.metrics.port_status.labels(
                dpid=hex(dp_id), port=port_no).set(port_status)
        else:
            self.logger.error(
                'port_status_handler: unknown %s', dpid_log(dp_id))
            ryu_dp.close()

    def get_config(self):
        """FAUCET API: return config for all Valves."""
        return get_config_for_api(self.valves)

    def get_tables(self, dp_id):
        """FAUCET API: return config tables for one Valve."""
        return self.valves[dp_id].dp.get_tables()
