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
    bgp = None
    metrics = None
    notifier = None
    valves_manager = None

    def __init__(self, *args, **kwargs):
        super(Faucet, self).__init__(*args, **kwargs)
        self.api = kwargs['faucet_experimental_api']
        self.metrics = faucet_metrics.FaucetMetrics(reg=self._reg)
        self.bgp = faucet_bgp.FaucetBgp(self.logger, self.metrics, self._send_flow_msgs)
        self.notifier = faucet_experimental_event.FaucetExperimentalEventNotifier(
            self.get_setting('EVENT_SOCK'), self.metrics, self.logger)
        self.valves_manager = valves_manager.ValvesManager(
            self.logname, self.logger, self.metrics, self.notifier, self.bgp, self._send_flow_msgs)

    @kill_on_exception(exc_logname)
    def start(self):
        super(Faucet, self).start()

        # Start Prometheus
        prom_port = int(self.get_setting('PROMETHEUS_PORT'))
        prom_addr = self.get_setting('PROMETHEUS_ADDR')
        self.metrics.start(prom_port, prom_addr)

        # Start event notifier
        notifier_thread = self.notifier.start()
        if notifier_thread is not None:
            self.threads.append(notifier_thread)

        # Start all threads
        self.threads.extend([
            hub.spawn(thread) for thread in (
                self._gateway_resolve_request, self._state_expire_request,
                self._metric_update_request, self._advertise_request,
                self._lldp_beacon_request)])

        # Register to API
        self.api._register(self)
        self.send_event_to_observers(EventFaucetExperimentalAPIRegistered())

    def _delete_deconfigured_dp(self, deleted_dpid):
        self.logger.info(
            'Deleting de-configured %s', dpid_log(deleted_dpid))
        ryu_dp = self.dpset.get(deleted_dpid)
        if ryu_dp is not None:
            ryu_dp.close()

    @set_ev_cls(EventReconfigure, MAIN_DISPATCHER)
    @kill_on_exception(exc_logname)
    def reload_config(self, ryu_event):
        """Handle a request to reload configuration."""
        super(Faucet, self).reload_config(ryu_event)
        self.valves_manager.request_reload_configs(
            self.config_file, delete_dp=self._delete_deconfigured_dp)

    @kill_on_exception(exc_logname)
    def _send_flow_msgs(self, valve, flow_msgs, ryu_dp=None):
        """Send OpenFlow messages to a connected datapath.

        Args:
            Valve instance or None.
            flow_msgs (list): OpenFlow messages to send.
            ryu_dp: Override datapath from DPSet.
        """
        if ryu_dp is None:
            ryu_dp = self.dpset.get(valve.dp.dp_id)
        if not ryu_dp:
            valve.logger.error('send_flow_msgs: DP not up')
            return
        valve.send_flows(ryu_dp, flow_msgs)

    def _get_valve(self, handler_name, ryu_event):
        """Get Valve instance to response to an event.

        Args:
            handler_name (string): handler name to log if datapath unknown.
            ryu_event (ryu.controller.event.Event): event
        Returns:
            valve, ryu_dp, msg: tuple of Nones, or datapath object, Ryu datapath, and Ryu msg (if any)
        """
        valve, ryu_dp, msg = self._get_datapath_obj(
            handler_name, self.valves_manager.valves, ryu_event)
        if valve and msg:
            valve.ofchannel_log([msg])
        return (valve, ryu_dp, msg)

    def _config_files_changed(self):
        return self.valves_manager.config_watcher.files_changed()

    def _metric_update_request(self):
        self._thread_reschedule(EventFaucetMetricUpdate(), 5)

    @set_ev_cls(EventFaucetMetricUpdate, MAIN_DISPATCHER)
    @kill_on_exception(exc_logname)
    def metric_update(self, _):
        """Handle a request to update metrics in the controller."""
        self.valves_manager.update_metrics()

    def _gateway_resolve_request(self):
        self._thread_reschedule(EventFaucetResolveGateways(), 2)

    def _state_expire_request(self):
        self._thread_reschedule(EventFaucetStateExpire(), 5)

    def _advertise_request(self):
        self._thread_reschedule(EventFaucetAdvertise(), 5)

    def _lldp_beacon_request(self):
        self._thread_reschedule(EventFaucetLLDPAdvertise(), 5)

    _VALVE_SERVICES = {
        EventFaucetResolveGateways: 'resolve_gateways',
        EventFaucetStateExpire: 'state_expire',
        EventFaucetAdvertise: 'advertise',
        EventFaucetLLDPAdvertise: 'send_lldp_beacons',
    }

    @set_ev_cls(EventFaucetResolveGateways, MAIN_DISPATCHER)
    @set_ev_cls(EventFaucetStateExpire, MAIN_DISPATCHER)
    @set_ev_cls(EventFaucetAdvertise, MAIN_DISPATCHER)
    @set_ev_cls(EventFaucetLLDPAdvertise, MAIN_DISPATCHER)
    @kill_on_exception(exc_logname)
    def _valve_flow_services(self, ryu_event):
        """Call a method on all Valves and send any resulting flows."""
        self.valves_manager.valve_flow_services(self._VALVE_SERVICES[type(ryu_event)])

    def get_config(self):
        """FAUCET experimental API: return config for all Valves."""
        return get_config_for_api(self.valves_manager.valves)

    def get_tables(self, dp_id):
        """FAUCET experimental API: return config tables for one Valve."""
        if dp_id in self.valves_manager.valves:
            return self.valves_manager.valves[dp_id].dp.get_tables()
        return {}

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER) # pylint: disable=no-member
    @kill_on_exception(exc_logname)
    def packet_in_handler(self, ryu_event):
        """Handle a packet in event from the dataplane.

        Args:
            ryu_event (ryu.controller.event.EventReplyBase): packet in message.
        """
        valve, _, msg = self._get_valve('packet_in_handler', ryu_event)
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
        valve, _, msg = self._get_valve('error_handler', ryu_event)
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
        valve, ryu_dp, msg = self._get_valve('features_handler', ryu_event)
        if valve is None:
            return
        flowmods = valve.switch_features(msg)
        self._send_flow_msgs(valve, flowmods, ryu_dp=ryu_dp)

    @kill_on_exception(exc_logname)
    def _datapath_connect(self, ryu_event):
        """Handle any/all re/connection of a datapath.

        Args:
            ryu_event (ryu.controller.ofp_event.Event)
        """
        valve, ryu_dp, _ = self._get_valve('_datapath_connect', ryu_event)
        if valve is None:
            return
        discovered_ports = [
            port for port in list(ryu_dp.ports.values()) if not valve_of.ignore_port(port.port_no)]
        flowmods = valve.datapath_connect(discovered_ports)
        self._send_flow_msgs(valve, flowmods)

    @kill_on_exception(exc_logname)
    def _datapath_disconnect(self, ryu_event):
        """Handle any/all disconnection of a datapath.

        Args:
            ryu_event (ryu.controller.ofp_event.Event)
        """
        valve, _, _ = self._get_valve('_datapath_disconnect', ryu_event)
        if valve is None:
            return
        valve.datapath_disconnect()

    @set_ev_cls(ofp_event.EventOFPDescStatsReply, MAIN_DISPATCHER) # pylint: disable=no-member
    @kill_on_exception(exc_logname)
    def desc_stats_reply_handler(self, ryu_event):
        """Handle OFPDescStatsReply from datapath.

        Args:
            ryu_event (ryu.controller.ofp_event.EventOFPDescStatsReply): trigger.
        """
        valve, _, msg = self._get_valve('desc_stats_reply_handler', ryu_event)
        if valve is None:
            return
        body = msg.body
        valve.ofdescstats_handler(body)

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER) # pylint: disable=no-member
    @kill_on_exception(exc_logname)
    def port_status_handler(self, ryu_event):
        """Handle a port status change event.

        Args:
            ryu_event (ryu.controller.ofp_event.EventOFPPortStatus): trigger.
        """
        valve, _, msg = self._get_valve('port_status_handler', ryu_event)
        if valve is None:
            return
        if not valve.dp.running:
            return
        port_no = msg.desc.port_no
        reason = msg.reason
        state = msg.desc.state
        valve.logger.info('port state %u (reason %u)' % (state, reason))
        port_status = valve_of.port_status_from_state(state)
        flowmods = valve.port_status_handler(
            port_no, reason, port_status)
        self._send_flow_msgs(valve, flowmods)

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER) # pylint: disable=no-member
    @kill_on_exception(exc_logname)
    def flowremoved_handler(self, ryu_event):
        """Handle a flow removed event.

        Args:
            ryu_event (ryu.controller.ofp_event.EventOFPFlowRemoved): trigger.
        """
        valve, ryu_dp, msg = self._get_valve('flowremoved_handler', ryu_event)
        if valve is None:
            return
        ofp = ryu_dp.ofproto
        reason = msg.reason
        if reason == ofp.OFPRR_IDLE_TIMEOUT:
            flowmods = valve.flow_timeout(msg.table_id, msg.match)
            self._send_flow_msgs(valve, flowmods)
