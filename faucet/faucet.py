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
import random
import signal
import sys
import time

from ryu.base import app_manager
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.controller import dpset
from ryu.controller import event
from ryu.controller import ofp_event
from ryu.lib import hub

from faucet.conf import InvalidConfigError
from faucet.config_parser import dp_parser, get_config_for_api
from faucet.config_parser_util import config_changed
from faucet.valve_util import dpid_log, get_logger, kill_on_exception, get_bool_setting, get_setting
from faucet.valve import valve_factory, SUPPORTED_HARDWARE
from faucet import faucet_experimental_api
from faucet import faucet_experimental_event
from faucet import faucet_bgp
from faucet import faucet_metrics
from faucet import valve_util
from faucet import valve_packet
from faucet import valve_of


class EventFaucetExperimentalAPIRegistered(event.EventBase):
    """Event used to notify that the API is registered with Faucet."""
    pass


class EventFaucetReconfigure(event.EventBase):
    """Event used to trigger FAUCET reconfiguration."""
    pass


class EventFaucetResolveGateways(event.EventBase):
    """Event used to trigger gateway re/resolution."""
    pass


class EventFaucetStateExpire(event.EventBase):
    """Event used to trigger expiration of state in controller."""
    pass


class EventFaucetMetricUpdate(event.EventBase):
    """Event used to trigger update of metrics."""
    pass


class EventFaucetAdvertise(event.EventBase):
    """Event used to trigger periodic network advertisements (eg IPv6 RAs)."""
    pass

class EventFaucetStackNeighbourDiscovery(event.EventBase):
    """Event used to trigger checking of link integrity in stacks."""
    pass

class Faucet(app_manager.RyuApp):
    """A RyuApp that implements an L2/L3 learning VLAN switch.

    Valve provides the switch implementation; this is a shim for the Ryu
    event handling framework to interface with Valve.
    """
    OFP_VERSIONS = valve_of.OFP_VERSIONS
    _CONTEXTS = {
        'dpset': dpset.DPSet,
        'faucet_experimental_api': faucet_experimental_api.FaucetExperimentalAPI,
        }
    _EVENTS = [EventFaucetExperimentalAPIRegistered]
    logname = 'faucet'
    exc_logname = logname + '.exception'

    def __init__(self, *args, **kwargs):
        super(Faucet, self).__init__(*args, **kwargs)

        # There doesnt seem to be a sensible method of getting command line
        # options into ryu apps. Instead I am using the environment variable
        # FAUCET_CONFIG to allow this to be set, if it is not set it will
        # default to valve.yaml
        self.config_file = get_setting('FAUCET_CONFIG')
        self.loglevel = get_setting('FAUCET_LOG_LEVEL')
        self.logfile = get_setting('FAUCET_LOG')
        self.exc_logfile = get_setting('FAUCET_EXCEPTION_LOG')
        self.stat_reload = get_bool_setting('FAUCET_CONFIG_STAT_RELOAD')

        self.dpset = kwargs['dpset']
        self.api = kwargs['faucet_experimental_api']

        # Setup logging
        self.logger = get_logger(
            self.logname, self.logfile, self.loglevel, 0)
        # Set up separate logging for exceptions
        self.exc_logger = get_logger(
            self.exc_logname, self.exc_logfile, logging.DEBUG, 1)

        self.valves = {}
        self.config_hashes = None
        self.config_file_stats = None
        self.metrics = faucet_metrics.FaucetMetrics()
        self.notifier = faucet_experimental_event.FaucetExperimentalEventNotifier(
            get_setting('FAUCET_EVENT_SOCK'), self.metrics, self.logger)
        self._bgp = faucet_bgp.FaucetBgp(self.logger, self._send_flow_msgs)

    @kill_on_exception(exc_logname)
    def start(self):
        super(Faucet, self).start()

        # Start event notifier
        notifier_thread = self.notifier.start()
        if notifier_thread is not None:
            self.threads.append(notifier_thread)

        # Start Prometheus
        prom_port = int(get_setting('FAUCET_PROMETHEUS_PORT'))
        prom_addr = get_setting('FAUCET_PROMETHEUS_ADDR')
        self.metrics.start(prom_port, prom_addr)

        # Configure all Valves
        if self.stat_reload:
            self.logger.info('will automatically reload new config on changes')
        self._load_configs(self.config_file)

        # Start all threads
        self.threads.extend([
            hub.spawn(thread) for thread in (
                self._gateway_resolve_request, self._state_expire_request,
                self._metric_update_request, self._advertise_request,
                self._config_file_stat, self._stack_neighbour_discovery_request)])
        

        # Register to API
        self.api._register(self)
        self.send_event_to_observers(EventFaucetExperimentalAPIRegistered())

        # Set the signal handler for reloading config file
        signal.signal(signal.SIGHUP, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)

    def _apply_configs_existing(self, dp_id, new_dp):
        logging.info('Reconfiguring existing datapath %s', dpid_log(dp_id))
        valve = self.valves[dp_id]
        cold_start, flowmods = valve.reload_config(new_dp)
        if flowmods:
            if cold_start:
                self.metrics.faucet_config_reload_cold.labels( # pylint: disable=no-member
                    **valve.base_prom_labels).inc()
                self.logger.info('Cold starting %s', dpid_log(dp_id))
            else:
                self.metrics.faucet_config_reload_warm.labels( # pylint: disable=no-member
                    **valve.base_prom_labels).inc()
                self.logger.info('Warm starting %s', dpid_log(dp_id))
            self._send_flow_msgs(new_dp.dp_id, flowmods)
            return valve
        self.logger.info('No changes to datapath %s', dpid_log(dp_id))
        return None

    def _apply_configs_new(self, dp_id, new_dp):
        self.logger.info('Add new datapath %s', dpid_log(dp_id))
        valve_cl = valve_factory(new_dp)
        if valve_cl is not None:
            return valve_cl(new_dp, self.logname, self.notifier)
        self.logger.error(
            '%s hardware %s must be one of %s',
            new_dp.name,
            new_dp.hardware,
            sorted(list(SUPPORTED_HARDWARE.keys())))
        return None

    def _apply_configs(self, new_dps):
        """Actually apply configs, if there were any differences."""
        deleted_valve_dpids = (
            set(list(self.valves.keys())) -
            set([valve.dp_id for valve in new_dps]))
        for new_dp in new_dps:
            dp_id = new_dp.dp_id
            if dp_id in self.valves:
                valve = self._apply_configs_existing(dp_id, new_dp)
            else:
                valve = self._apply_configs_new(dp_id, new_dp)
            if valve is not None:
                self.valves[dp_id] = valve
                self.metrics.reset_dpid(valve.base_prom_labels)
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
    def _load_configs(self, new_config_file):
        try:
            new_config_hashes, new_dps = dp_parser(new_config_file, self.logname)
            self.config_file = new_config_file
            self.config_hashes = new_config_hashes
            self._apply_configs(new_dps)
        except InvalidConfigError as err:
            self.logger.error('New config bad (%s) - rejecting', err)
            return

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
        reordered_flow_msgs = valve_of.valve_flowreorder(flow_msgs)
        valve.ofchannel_log(reordered_flow_msgs)
        for flow_msg in reordered_flow_msgs:
            self.metrics.of_flowmsgs_sent.labels( # pylint: disable=no-member
                **valve.base_prom_labels).inc()
            flow_msg.datapath = ryu_dp
            ryu_dp.send_msg(flow_msg)
            if valve.recent_ofmsgs.full():
                valve.recent_ofmsgs.get()
            valve.recent_ofmsgs.put(flow_msg)

    def _get_valve(self, ryu_dp, handler_name, msg=None):
        """Get Valve instance to response to an event.

        Args:
            ryu_dp (ryu.controller.controller.Datapath): datapath.
            handler_name (string): handler name to log if datapath unknown.
            msg (ryu.controller.ofp_event.EventOFPMsgBase): message from datapath.
        Returns:
            Valve instance or None.
        """
        dp_id = ryu_dp.id
        if dp_id in self.valves:
            valve = self.valves[dp_id]
            if msg:
                valve.ofchannel_log([msg])
            return valve
        ryu_dp.close()
        self.logger.error(
            '%s: unknown datapath %s', handler_name, dpid_log(dp_id))
        return None

    def _signal_handler(self, sigid, _):
        """Handle any received signals.

        Args:
            sigid (int): signal to handle.
        """
        if sigid == signal.SIGHUP:
            self.send_event('Faucet', EventFaucetReconfigure())
        elif sigid == signal.SIGINT:
            self.close()
            sys.exit(0)

    @staticmethod
    def _thread_jitter(period, jitter=2):
        """Reschedule another thread with a random jitter."""
        hub.sleep(period + random.randint(0, jitter))

    def _thread_reschedule(self, ryu_event, period, jitter=2):
        """Trigger Ryu events periodically with a jitter.

        Args:
            ryu_event (ryu.controller.event.EventReplyBase): event to trigger.
            period (int): how often to trigger.
        """
        while True:
            self.send_event('Faucet', ryu_event)
            self._thread_jitter(period, jitter)

    @kill_on_exception(exc_logname)
    def _config_file_stat(self):
        """Periodically stat config files for any changes."""
        # TODO: Better to use an inotify method that doesn't conflict with eventlets.
        while True:
            if self.config_hashes:
                new_config_file_stats = valve_util.stat_config_files(
                    self.config_hashes)
                if self.config_file_stats:
                    if new_config_file_stats != self.config_file_stats:
                        if self.stat_reload:
                            self.send_event('Faucet', EventFaucetReconfigure())
                        self.logger.info('config file(s) changed on disk')
                self.config_file_stats = new_config_file_stats
            self._thread_jitter(3)

    def _gateway_resolve_request(self):
        self._thread_reschedule(EventFaucetResolveGateways(), 2)

    def _state_expire_request(self):
        self._thread_reschedule(EventFaucetStateExpire(), 5)

    def _metric_update_request(self):
        self._thread_reschedule(EventFaucetMetricUpdate(), 5)

    def _advertise_request(self):
        self._thread_reschedule(EventFaucetAdvertise(), 5)

    def _stack_neighbour_discovery_request(self):
        self._thread_reschedule(EventFaucetStackNeighbourDiscovery(), 2)

    @set_ev_cls(EventFaucetResolveGateways, MAIN_DISPATCHER)
    @kill_on_exception(exc_logname)
    def resolve_gateways(self, _):
        """Handle a request to re/resolve gateways."""
        for dp_id, valve in list(self.valves.items()):
            flowmods = valve.resolve_gateways()
            if flowmods:
                self._send_flow_msgs(dp_id, flowmods)

    @set_ev_cls(EventFaucetStateExpire, MAIN_DISPATCHER)
    @kill_on_exception(exc_logname)
    def state_expire(self, _):
        """Handle a request expire host state in the controller."""
        for dp_id, valve in list(self.valves.items()):
            flowmods = valve.state_expire()
            if flowmods:
                self._send_flow_msgs(dp_id, flowmods)

    @set_ev_cls(EventFaucetMetricUpdate, MAIN_DISPATCHER)
    @kill_on_exception(exc_logname)
    def metric_update(self, _):
        """Handle a request to update metrics in the controller."""
        self._bgp.update_metrics()
        for valve in list(self.valves.values()):
            valve.update_metrics(self.metrics)

    @set_ev_cls(EventFaucetAdvertise, MAIN_DISPATCHER)
    @kill_on_exception(exc_logname)
    def advertise(self, _):
        """Handle a request to advertise services."""
        for dp_id, valve in list(self.valves.items()):
            flowmods = valve.advertise()
            if flowmods:
                self._send_flow_msgs(dp_id, flowmods)

    @set_ev_cls(EventFaucetStackNeighbourDiscovery, MAIN_DISPATCHER)
    @kill_on_exception(exc_logname)
    def neighbour_discovery(self, _):
        """Handle a request to rediscover neighbours on dps in a stack."""
        for dp_id, valve in list(self.valves.items()):
            flowmods = valve.stack_neighbour_discovery()
            self._send_flow_msgs(dp_id, flowmods)

    def get_config(self):
        """FAUCET experimental API: return config for all Valves."""
        return get_config_for_api(self.valves)

    def get_tables(self, dp_id):
        """FAUCET experimental API: return config tables for one Valve."""
        return self.valves[dp_id].dp.get_tables()

    @set_ev_cls(EventFaucetReconfigure, MAIN_DISPATCHER)
    @kill_on_exception(exc_logname)
    def reload_config(self, _):
        """Handle a request to reload configuration."""
        self.logger.info('request to reload configuration')
        new_config_file = self.config_file
        if config_changed(self.config_file, new_config_file, self.config_hashes):
            self.logger.info('configuration %s changed, analyzing differences', new_config_file)
            self._load_configs(new_config_file)
        else:
            self.logger.info('configuration is unchanged, not reloading')
        self.metrics.faucet_config_reload_requests.inc() # pylint: disable=no-member

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER) # pylint: disable=no-member
    @kill_on_exception(exc_logname)
    def packet_in_handler(self, ryu_event):
        """Handle a packet in event from the dataplane.

        Args:
            ryu_event (ryu.controller.event.EventReplyBase): packet in message.
        """
        msg = ryu_event.msg
        ryu_dp = msg.datapath
        dp_id = ryu_dp.id
        valve = self._get_valve(ryu_dp, 'packet_in_handler', msg)
        if valve is None:
            return
        if not valve.dp.running:
            return
        if valve.dp.cookie != msg.cookie:
            return
        in_port = msg.match['in_port']
        if valve_of.ignore_port(in_port):
            return

        # Truncate packet in data (OVS > 2.5 does not honor max_len)
        msg.data = msg.data[:valve_of.MAX_PACKET_IN_BYTES]

        # eth/VLAN header only
        pkt, eth_pkt, vlan_vid, eth_type = valve_packet.parse_packet_in_pkt(
            msg.data, max_len=valve_packet.ETH_VLAN_HEADER_SIZE)
        if vlan_vid is None:
            self.logger.info(
                'packet without VLAN header from %s port %s', dpid_log(dp_id), in_port)
            return
        if pkt is None:
            self.logger.info(
                'unparseable packet from %s port %s', dpid_log(dp_id), in_port)
            return
        if vlan_vid not in valve.dp.vlans:
            self.logger.info(
                'packet for unknown VLAN %u from %s', vlan_vid, dpid_log(dp_id))
            return
        if in_port not in valve.dp.ports:
            self.logger.info(
                'packet for unknown port %u from %s', in_port, dpid_log(dp_id))
            return
        pkt_meta = valve.parse_rcv_packet(
            in_port, vlan_vid, eth_type, msg.data, msg.total_len, pkt, eth_pkt)
        other_valves = [other_valve for other_valve in list(self.valves.values()) if valve != other_valve]

        self.metrics.of_packet_ins.labels( # pylint: disable=no-member
            **valve.base_prom_labels).inc()
        packet_in_start = time.time()
        flowmods = valve.rcv_packet(other_valves, pkt_meta)
        packet_in_stop = time.time()
        self.metrics.faucet_packet_in_secs.labels( # pylint: disable=no-member
            **valve.base_prom_labels).observe(packet_in_stop - packet_in_start)
        self._send_flow_msgs(dp_id, flowmods)
        valve.update_metrics(self.metrics)

    @set_ev_cls(ofp_event.EventOFPErrorMsg, MAIN_DISPATCHER) # pylint: disable=no-member
    @kill_on_exception(exc_logname)
    def error_handler(self, ryu_event):
        """Handle an OFPError from a datapath.

        Args:
            ryu_event (ryu.controller.ofp_event.EventOFPErrorMsg): trigger
        """
        msg = ryu_event.msg
        ryu_dp = msg.datapath
        dp_id = ryu_dp.id
        valve = self._get_valve(ryu_dp, 'error_handler', msg)
        if valve is None:
            return
        self.metrics.of_errors.labels( # pylint: disable=no-member
            **valve.base_prom_labels).inc()
        error_txt = msg
        while not valve.recent_ofmsgs.empty():
            flow_msg = valve.recent_ofmsgs.get()
            if msg.xid == flow_msg.xid:
                error_txt = '%s caused by %s' % (msg, flow_msg)
                break
        self.logger.error('%s OFError %s', dpid_log(dp_id), error_txt)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER) # pylint: disable=no-member
    @kill_on_exception(exc_logname)
    def features_handler(self, ryu_event):
        """Handle receiving a switch features message from a datapath.

        Args:
            ryu_event (ryu.controller.ofp_event.EventOFPStateChange): trigger.
        """
        msg = ryu_event.msg
        ryu_dp = msg.datapath
        dp_id = ryu_dp.id
        valve = self._get_valve(ryu_dp, 'features_handler', msg)
        if valve is None:
            return
        flowmods = valve.switch_features(msg)
        self._send_flow_msgs(dp_id, flowmods, ryu_dp=ryu_dp)

    @kill_on_exception(exc_logname)
    def _datapath_connect(self, ryu_dp):
        """Handle any/all re/connection of a datapath.

        Args:
            ryu_dp (ryu.controller.controller.Datapath): datapath.
        """
        def port_up_valid(port):
            """Return True if port is up and in valid range."""
            return port.state == 0 and not valve_of.ignore_port(port.port_no)

        dp_id = ryu_dp.id
        valve = self._get_valve(ryu_dp, '_datapath_connect')
        if valve is None:
            return
        discovered_up_port_nums = [
            port.port_no for port in list(ryu_dp.ports.values()) if port_up_valid(port)]
        flowmods = valve.datapath_connect(discovered_up_port_nums)
        self._send_flow_msgs(dp_id, flowmods)
        self.metrics.of_dp_connections.labels( # pylint: disable=no-member
            **valve.base_prom_labels).inc()
        self.metrics.dp_status.labels( # pylint: disable=no-member
            **valve.base_prom_labels).set(1)

    @kill_on_exception(exc_logname)
    def _datapath_disconnect(self, ryu_dp):
        """Handle any/all disconnection of a datapath.

        Args:
            ryu_dp (ryu.controller.controller.Datapath): datapath.
        """
        valve = self._get_valve(ryu_dp, '_datapath_disconnect')
        if valve is None:
            return
        valve.datapath_disconnect()
        self.metrics.of_dp_disconnections.labels( # pylint: disable=no-member
            **valve.base_prom_labels).inc()
        self.metrics.dp_status.labels( # pylint: disable=no-member
            **valve.base_prom_labels).set(0)

    @set_ev_cls(dpset.EventDP, dpset.DPSET_EV_DISPATCHER)
    @kill_on_exception(exc_logname)
    def connect_or_disconnect_handler(self, ryu_event):
        """Handle connection or disconnection of a datapath.

        Args:
            ryu_event (ryu.controller.dpset.EventDP): trigger.
        """
        ryu_dp = ryu_event.dp
        dp_id = ryu_dp.id
        valve = self._get_valve(ryu_dp, 'handler_connect_or_disconnect')
        if valve is None:
            return
        if ryu_event.enter:
            self.logger.info('%s connected', dpid_log(dp_id))
            self._datapath_connect(ryu_dp)
        else:
            self.logger.info('%s disconnected', dpid_log(dp_id))
            self._datapath_disconnect(ryu_dp)

    @set_ev_cls(dpset.EventDPReconnected, dpset.DPSET_EV_DISPATCHER)
    @kill_on_exception(exc_logname)
    def reconnect_handler(self, ryu_event):
        """Handle reconnection of a datapath.

        Args:
            ryu_event (ryu.controller.dpset.EventDPReconnected): trigger.
        """
        ryu_dp = ryu_event.dp
        dp_id = ryu_dp.id
        valve = self._get_valve(ryu_dp, 'reconnect_handler')
        if valve is None:
            return
        self.logger.debug('%s reconnected', dpid_log(dp_id))
        self._datapath_connect(ryu_dp)

    @set_ev_cls(ofp_event.EventOFPDescStatsReply, MAIN_DISPATCHER) # pylint: disable=no-member
    @kill_on_exception(exc_logname)
    def desc_stats_reply_handler(self, ryu_event):
        """Handle OFPDescStatsReply from datapath.

        Args:
            ryu_event (ryu.controller.ofp_event.EventOFPDescStatsReply): trigger.
        """
        ryu_dp = ryu_event.msg.datapath
        dp_id = ryu_dp.id
        valve = self._get_valve(ryu_dp, 'desc_stats_reply_handler')
        if valve is None:
            return
        body = ryu_event.msg.body
        self.metrics.of_dp_desc_stats.labels( # pylint: disable=no-member
            **dict(valve.base_prom_labels,
                   mfr_desc=body.mfr_desc,
                   hw_desc=body.hw_desc,
                   sw_desc=body.sw_desc,
                   serial_num=body.serial_num,
                   dp_desc=body.dp_desc)).set(dp_id)

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
        valve = self._get_valve(ryu_dp, 'port_status_handler', msg)
        if valve is None:
            return
        if not valve.dp.running:
            return
        port_no = msg.desc.port_no
        if valve_of.ignore_port(port_no):
            return
        ofp = msg.datapath.ofproto
        reason = msg.reason
        port_down = msg.desc.state & ofp.OFPPS_LINK_DOWN
        port_status = not port_down
        flowmods = valve.port_status_handler(
            port_no, reason, port_status)
        self._send_flow_msgs(dp_id, flowmods)
        port_labels = dict(valve.base_prom_labels, port=port_no)
        self.metrics.port_status.labels( # pylint: disable=no-member
            **port_labels).set(port_status)

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER) # pylint: disable=no-member
    @kill_on_exception(exc_logname)
    def flowremoved_handler(self, ryu_event):
        """Handle a flow removed event.

        Args:
            ryu_event (ryu.controller.ofp_event.EventOFPFlowRemoved): trigger.
        """
        msg = ryu_event.msg
        ryu_dp = msg.datapath
        valve = self._get_valve(ryu_dp, 'flowremoved_handler', msg)
        if valve is None:
            return
        ofp = msg.datapath.ofproto
        reason = msg.reason
        if reason == ofp.OFPRR_IDLE_TIMEOUT:
            flowmods = valve.flow_timeout(msg.table_id, msg.match)
            if flowmods:
                self._send_flow_msgs(ryu_dp.id, flowmods)
