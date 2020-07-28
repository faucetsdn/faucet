"""RyuApp shim between Ryu and Valve."""

# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2015 Brad Cowie, Christopher Lorier and Joe Stringer.
# Copyright (C) 2015 Research and Education Advanced Network New Zealand Ltd.
# Copyright (C) 2015--2019 The Contributors
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

import time

from functools import partial

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
from faucet import faucet_event
from faucet import faucet_bgp
from faucet import faucet_dot1x
from faucet import valves_manager
from faucet import faucet_metrics
from faucet import valve_of


EXPORT_RYU_CONFIGS = ['echo_request_interval', 'maximum_unreplied_echo_requests']


class EventFaucetMaintainStackRoot(event.EventBase):  # pylint: disable=too-few-public-methods
    """Event used to maintain stack root."""


class EventFaucetMetricUpdate(event.EventBase):  # pylint: disable=too-few-public-methods
    """Event used to trigger update of metrics."""


class EventFaucetResolveGateways(event.EventBase):  # pylint: disable=too-few-public-methods
    """Event used to trigger gateway re/resolution."""


class EventFaucetStateExpire(event.EventBase):  # pylint: disable=too-few-public-methods
    """Event used to trigger expiration of state in controller."""


class EventFaucetFastStateExpire(event.EventBase):  # pylint: disable=too-few-public-methods
    """Event used to trigger fast expiration of state in controller."""


class EventFaucetAdvertise(event.EventBase):  # pylint: disable=too-few-public-methods
    """Event used to trigger periodic network advertisements (eg IPv6 RAs)."""


class EventFaucetFastAdvertise(event.EventBase):  # pylint: disable=too-few-public-methods
    """Event used to trigger periodic fast network advertisements (eg LACP)."""


class EventFaucetEventSockHeartbeat(event.EventBase):  # pylint: disable=too-few-public-methods
    """Event used to trigger periodic events on event sock, causing it to raise an exception if conn is broken."""


class Faucet(RyuAppBase):
    """A RyuApp that implements an L2/L3 learning VLAN switch.

    Valve provides the switch implementation; this is a shim for the Ryu
    event handling framework to interface with Valve.
    """
    _CONTEXTS = {
        'dpset': dpset.DPSet,
        }
    _VALVE_SERVICES = {
        EventFaucetMetricUpdate: (None, 5),
        EventFaucetMaintainStackRoot: (None, valves_manager.STACK_ROOT_STATE_UPDATE_TIME),
        EventFaucetResolveGateways: ('resolve_gateways', 2),
        EventFaucetStateExpire: ('state_expire', 5),
        EventFaucetFastStateExpire: ('fast_state_expire', 2),
        EventFaucetAdvertise: ('advertise', 15),
        EventFaucetFastAdvertise: ('fast_advertise', 5),
    }
    logname = 'faucet'
    exc_logname = logname + '.exception'
    bgp = None
    notifier = None
    valves_manager = None
    event_socket_heartbeat_time = 0

    def __init__(self, *args, **kwargs):
        super(Faucet, self).__init__(*args, **kwargs)
        self.prom_client = faucet_metrics.FaucetMetrics(reg=self._reg)
        self.bgp = faucet_bgp.FaucetBgp(
            self.logger, self.exc_logname, self.prom_client, self._send_flow_msgs)
        self.dot1x = faucet_dot1x.FaucetDot1x(
            self.logger, self.exc_logname, self.prom_client, self._send_flow_msgs)
        self.notifier = faucet_event.FaucetEventNotifier(
            self.get_setting('EVENT_SOCK'), self.prom_client, self.logger)
        self.valves_manager = valves_manager.ValvesManager(
            self.logname, self.logger, self.prom_client, self.notifier, self.bgp,
            self.dot1x, self.get_setting('CONFIG_AUTO_REVERT'), self._send_flow_msgs)
        self.thread_managers = (self.bgp, self.dot1x, self.prom_client, self.notifier)
        self.event_sock_hrtbeat_time = int(self.get_setting('EVENT_SOCK_HEARTBEAT') or 0)
        if self.event_sock_hrtbeat_time > 0:
            self._VALVE_SERVICES[EventFaucetEventSockHeartbeat] = ('event_sock_heartbeat', self.event_sock_hrtbeat_time)

    @kill_on_exception(exc_logname)
    def _check_thread_exception(self):
        super(Faucet, self)._check_thread_exception()

    def _export_ryu_config(self):
        for opt_name in EXPORT_RYU_CONFIGS:
            value = int(getattr(self.CONF, opt_name))
            config_labels = dict(param=opt_name)
            self.prom_client.ryu_config.labels(**config_labels).set(value)

    @kill_on_exception(exc_logname)
    def start(self):
        super(Faucet, self).start()

        # Start Prometheus
        prom_port = int(self.get_setting('PROMETHEUS_PORT'))
        prom_addr = self.get_setting('PROMETHEUS_ADDR')
        self.prom_client.start(prom_port, prom_addr)
        self._export_ryu_config()

        # Start event notifier
        notifier_thread = self.notifier.start()
        if notifier_thread is not None:
            self.threads.append(notifier_thread)

        for service_event, service_pair in self._VALVE_SERVICES.items():
            name, interval = service_pair
            thread = hub.spawn(
                partial(self._thread_reschedule, service_event(), interval))
            thread.name = name
            self.threads.append(thread)

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
            time.time(), self.config_file, delete_dp=self._delete_deconfigured_dp)

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
        valve.send_flows(ryu_dp, flow_msgs, time.time())

    def _get_valve(self, ryu_event, require_running=False):
        """Get Valve instance to response to an event.

        Args:
            ryu_event (ryu.controller.event.Event): event
            require_running (bool): require DP to be running.
        Returns:
            valve, ryu_dp, msg: tuple of Nones, or datapath object, Ryu datapath, and msg (if any)
        """
        valve, ryu_dp, msg = self._get_datapath_obj(
            self.valves_manager.valves, ryu_event)
        if valve:
            if msg:
                valve.ofchannel_log([msg])
            if require_running and not valve.dp.dyn_running:
                valve = None
        return (valve, ryu_dp, msg)

    def _config_files_changed(self):
        return self.valves_manager.config_watcher.files_changed()

    @set_ev_cls(EventFaucetMetricUpdate, MAIN_DISPATCHER)
    @kill_on_exception(exc_logname)
    def metric_update(self, _):
        """Handle a request to update metrics in the controller."""
        self.valves_manager.update_metrics(time.time())

    @set_ev_cls(EventFaucetMaintainStackRoot, MAIN_DISPATCHER)
    @kill_on_exception(exc_logname)
    def _maintain_stack_root(self, _):
        self.valves_manager.maintain_stack_root(time.time())

    @set_ev_cls(EventFaucetEventSockHeartbeat, MAIN_DISPATCHER)
    @kill_on_exception(exc_logname)
    def _event_socket_heartbeat(self, _):
        self.valves_manager.event_socket_heartbeat(time.time())

    @set_ev_cls(EventFaucetResolveGateways, MAIN_DISPATCHER)
    @set_ev_cls(EventFaucetStateExpire, MAIN_DISPATCHER)
    @set_ev_cls(EventFaucetFastStateExpire, MAIN_DISPATCHER)
    @set_ev_cls(EventFaucetAdvertise, MAIN_DISPATCHER)
    @set_ev_cls(EventFaucetFastAdvertise, MAIN_DISPATCHER)
    @kill_on_exception(exc_logname)
    def _valve_flow_services(self, ryu_event):
        """Call a method on all Valves and send any resulting flows."""
        self.valves_manager.valve_flow_services(
            time.time(),
            self._VALVE_SERVICES[type(ryu_event)][0])

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER) # pylint: disable=no-member
    @kill_on_exception(exc_logname)
    def packet_in_handler(self, ryu_event):
        """Handle a packet in event from the dataplane.

        Args:
            ryu_event (ryu.controller.event.EventReplyBase): packet in message.
        """
        valve, _, msg = self._get_valve(ryu_event, require_running=True)
        if valve is None:
            return
        self.valves_manager.valve_packet_in(ryu_event.timestamp, valve, msg)

    @set_ev_cls(ofp_event.EventOFPErrorMsg, MAIN_DISPATCHER) # pylint: disable=no-member
    @kill_on_exception(exc_logname)
    def error_handler(self, ryu_event):
        """Handle an OFPError from a datapath.

        Args:
            ryu_event (ryu.controller.ofp_event.EventOFPErrorMsg): trigger
        """
        valve, _, msg = self._get_valve(ryu_event)
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
        valve, ryu_dp, msg = self._get_valve(ryu_event)
        if valve is None:
            return
        self._send_flow_msgs(valve, valve.switch_features(msg), ryu_dp=ryu_dp)

    @kill_on_exception(exc_logname)
    def _datapath_connect(self, ryu_event):
        """Handle any/all re/connection of a datapath.

        Args:
            ryu_event (ryu.controller.ofp_event.Event)
        """
        now = time.time()
        valve, ryu_dp, _ = self._get_valve(ryu_event)
        if valve is None:
            return
        discovered_up_ports = {
            port.port_no for port in list(ryu_dp.ports.values())
            if (valve_of.port_status_from_state(port.state) and
                not valve_of.ignore_port(port.port_no))}
        self._send_flow_msgs(
            valve, self.valves_manager.datapath_connect(now, valve, discovered_up_ports))
        self.valves_manager.update_config_applied({valve.dp.dp_id: True})

    @kill_on_exception(exc_logname)
    def _datapath_disconnect(self, ryu_event):
        """Handle any/all disconnection of a datapath.

        Args:
            ryu_event (ryu.controller.ofp_event.Event)
        """
        valve, _, _ = self._get_valve(ryu_event)
        if valve is None:
            return
        valve.datapath_disconnect(time.time())

    @set_ev_cls(ofp_event.EventOFPDescStatsReply, MAIN_DISPATCHER) # pylint: disable=no-member
    @kill_on_exception(exc_logname)
    def desc_stats_reply_handler(self, ryu_event):
        """Handle OFPDescStatsReply from datapath.

        Args:
            ryu_event (ryu.controller.ofp_event.EventOFPDescStatsReply): trigger.
        """
        valve, _, msg = self._get_valve(ryu_event)
        if valve is None:
            return
        valve.ofdescstats_handler(msg.body)

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER) # pylint: disable=no-member
    @kill_on_exception(exc_logname)
    def port_status_handler(self, ryu_event):
        """Handle a port status change event.

        Args:
            ryu_event (ryu.controller.ofp_event.EventOFPPortStatus): trigger.
        """
        valve, _, msg = self._get_valve(ryu_event, require_running=True)
        if valve is None:
            return
        self.valves_manager.port_status_handler(valve, msg, time.time())

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER) # pylint: disable=no-member
    @kill_on_exception(exc_logname)
    def flowremoved_handler(self, ryu_event):
        """Handle a flow removed event.

        Args:
            ryu_event (ryu.controller.ofp_event.EventOFPFlowRemoved): trigger.
        """
        valve, ryu_dp, msg = self._get_valve(ryu_event, require_running=True)
        if valve is None:
            return
        if msg.reason == ryu_dp.ofproto.OFPRR_IDLE_TIMEOUT:
            self._send_flow_msgs(valve, valve.flow_timeout(time.time(), msg.table_id, msg.match))
