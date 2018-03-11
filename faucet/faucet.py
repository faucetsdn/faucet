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

from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.controller import dpset
from ryu.controller import event
from ryu.controller import ofp_event
from ryu.lib import hub

from faucet.config_parser import get_config_for_api
from faucet.valve_ryuapp import EventReconfigure, RyuAppBase
from faucet.valve_util import dpid_log, kill_on_exception
from faucet import faucet_experimental_api
from faucet import faucet_experimental_event
from faucet import faucet_bgp
from faucet import valves_manager
from faucet import faucet_metrics
from faucet import valve_of


class EventFaucetExperimentalAPIRegistered(event.EventBase):
    """Event used to notify that the API is registered with Faucet."""
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


class EventFaucetLLDPAdvertise(event.EventBase):
    """Event used to trigger periodic LLDP beacons."""
    pass


class Faucet(RyuAppBase):
    """A RyuApp that implements an L2/L3 learning VLAN switch.

    Valve provides the switch implementation; this is a shim for the Ryu
    event handling framework to interface with Valve.
    """
    _CONTEXTS = {
        'dpset': dpset.DPSet,
        'faucet_experimental_api': faucet_experimental_api.FaucetExperimentalAPI,
        }
    _EVENTS = [EventFaucetExperimentalAPIRegistered]
    logname = 'faucet'
    exc_logname = logname + '.exception'

    def __init__(self, *args, **kwargs):
        super(Faucet, self).__init__(*args, **kwargs)
        self.api = kwargs['faucet_experimental_api']
        self.metrics = faucet_metrics.FaucetMetrics()
        self.notifier = faucet_experimental_event.FaucetExperimentalEventNotifier(
            self.get_setting('EVENT_SOCK'), self.metrics, self.logger)
        self.bgp = faucet_bgp.FaucetBgp(self.logger, self.metrics, self._send_flow_msgs)
        self.valves_manager = valves_manager.ValvesManager(
            self.logname, self.logger, self.metrics, self.notifier, self.bgp, self._send_flow_msgs)

    @kill_on_exception(exc_logname)
    def start(self):
        super(Faucet, self).start()

        # Start event notifier
        notifier_thread = self.notifier.start()
        if notifier_thread is not None:
            self.threads.append(notifier_thread)

        # Start Prometheus
        prom_port = int(self.get_setting('PROMETHEUS_PORT'))
        prom_addr = self.get_setting('PROMETHEUS_ADDR')
        self.metrics.start(prom_port, prom_addr)

        # Configure all Valves
        self._load_configs(self.config_file)

        # Start all threads
        self.threads.extend([
            hub.spawn(thread) for thread in (
                self._gateway_resolve_request, self._state_expire_request,
                self._metric_update_request, self._advertise_request,
                self._config_file_stat, self._lldp_beacon_request)])

        # Register to API
        self.api._register(self)
        self.send_event_to_observers(EventFaucetExperimentalAPIRegistered())

    def _delete_deconfigured_dp(self, deleted_dpid):
        self.logger.info(
            'Deleting de-configured %s', dpid_log(deleted_dpid))
        ryu_dp = self.dpset.get(deleted_dpid)
        if ryu_dp is not None:
            ryu_dp.close()

    @kill_on_exception(exc_logname)
    def _load_configs(self, new_config_file):
        self.valves_manager.load_configs(
            new_config_file, delete_dp=self._delete_deconfigured_dp)

    @set_ev_cls(EventReconfigure, MAIN_DISPATCHER)
    @kill_on_exception(exc_logname)
    def reload_config(self, _):
        """Handle a request to reload configuration."""
        self.valves_manager.request_reload_configs(
            self.config_file, delete_dp=self._delete_deconfigured_dp)

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
            if dp_id not in self.valves_manager.valves:
                self.logger.error('send_flow_msgs: unknown %s', dpid_log(dp_id))
                return

        valve = self.valves_manager.valves[dp_id]
        valve.send_flows(ryu_dp, flow_msgs)

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
        if dp_id in self.valves_manager.valves:
            valve = self.valves_manager.valves[dp_id]
            if msg:
                valve.ofchannel_log([msg])
            return valve
        ryu_dp.close()
        self.logger.error(
            '%s: unknown datapath %s', handler_name, dpid_log(dp_id))
        return None

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
        while True:
            if self.valves_manager.config_watcher.files_changed():
                if self.stat_reload:
                    self.send_event('Faucet', EventReconfigure())
            self._thread_jitter(3)

    def _gateway_resolve_request(self):
        self._thread_reschedule(EventFaucetResolveGateways(), 2)

    def _state_expire_request(self):
        self._thread_reschedule(EventFaucetStateExpire(), 5)

    def _metric_update_request(self):
        self._thread_reschedule(EventFaucetMetricUpdate(), 5)

    def _advertise_request(self):
        self._thread_reschedule(EventFaucetAdvertise(), 5)

    def _lldp_beacon_request(self):
        self._thread_reschedule(EventFaucetLLDPAdvertise(), 5)

    def _valve_flow_services(self, valve_service):
        """Call a method on all Valves and send any resulting flows."""
        self.valves_manager.valve_flow_services(valve_service)

    @set_ev_cls(EventFaucetResolveGateways, MAIN_DISPATCHER)
    @kill_on_exception(exc_logname)
    def resolve_gateways(self, _):
        """Handle a request to re/resolve gateways."""
        self._valve_flow_services('resolve_gateways')

    @set_ev_cls(EventFaucetStateExpire, MAIN_DISPATCHER)
    @kill_on_exception(exc_logname)
    def state_expire(self, _):
        """Handle a request expire host state in the controller."""
        self._valve_flow_services('state_expire')

    @set_ev_cls(EventFaucetMetricUpdate, MAIN_DISPATCHER)
    @kill_on_exception(exc_logname)
    def metric_update(self, _):
        """Handle a request to update metrics in the controller."""
        self.valves_manager.update_metrics()

    @set_ev_cls(EventFaucetAdvertise, MAIN_DISPATCHER)
    @kill_on_exception(exc_logname)
    def advertise(self, _):
        """Handle a request to advertise services."""
        self._valve_flow_services('advertise')

    @set_ev_cls(EventFaucetLLDPAdvertise, MAIN_DISPATCHER)
    @kill_on_exception(exc_logname)
    def lldp_beacon(self, _):
        """Handle a request to advertise LLDP."""
        self._valve_flow_services('send_lldp_beacons')

    def get_config(self):
        """FAUCET experimental API: return config for all Valves."""
        return get_config_for_api(self.valves_manager.valves)

    def get_tables(self, dp_id):
        """FAUCET experimental API: return config tables for one Valve."""
        return self.valves_manager.valves[dp_id].dp.get_tables()

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER) # pylint: disable=no-member
    @kill_on_exception(exc_logname)
    def packet_in_handler(self, ryu_event):
        """Handle a packet in event from the dataplane.

        Args:
            ryu_event (ryu.controller.event.EventReplyBase): packet in message.
        """
        msg = ryu_event.msg
        ryu_dp = msg.datapath
        valve = self._get_valve(ryu_dp, 'packet_in_handler', msg)
        if valve is None:
            return
        if valve.rate_limit_packet_ins():
            return
        pkt_meta = valve.parse_pkt_meta(msg)
        if pkt_meta is None:
            return
        self.valves_manager.valve_packet_in(valve, pkt_meta)

    @set_ev_cls(ofp_event.EventOFPErrorMsg, MAIN_DISPATCHER) # pylint: disable=no-member
    @kill_on_exception(exc_logname)
    def error_handler(self, ryu_event):
        """Handle an OFPError from a datapath.

        Args:
            ryu_event (ryu.controller.ofp_event.EventOFPErrorMsg): trigger
        """
        msg = ryu_event.msg
        ryu_dp = msg.datapath
        valve = self._get_valve(ryu_dp, 'error_handler', msg)
        if valve is None:
            return
        valve.oferror(msg)

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
        dp_id = ryu_dp.id
        valve = self._get_valve(ryu_dp, '_datapath_connect')
        if valve is None:
            return
        discovered_ports = [
            port for port in list(ryu_dp.ports.values()) if not valve_of.ignore_port(port.port_no)]
        flowmods = valve.datapath_connect(discovered_ports)
        self._send_flow_msgs(dp_id, flowmods)

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
        body = ryu_event.msg.body
        valve = self._get_valve(ryu_dp, 'desc_stats_reply_handler')
        if valve is None:
            return
        valve.ofdescstats_handler(body)

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
        reason = msg.reason
        port_status = valve_of.port_status_from_state(msg.desc.state)
        self.logger.info(
            '%s port state %u (reason %u)',
            dpid_log(dp_id), msg.desc.state, reason)
        flowmods = valve.port_status_handler(
            port_no, reason, port_status)
        self._send_flow_msgs(dp_id, flowmods)

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
