"""Implementation of Valve learning layer 2/3 switch."""

# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2015 Brad Cowie, Christopher Lorier and Joe Stringer.
# Copyright (C) 2015 Research and Education Advanced Network New Zealand Ltd.
# Copyright (C) 2015--2018 The Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import copy
import logging
import random

from collections import defaultdict, deque

from faucet import tfm_pipeline
from faucet import valve_acl
from faucet import valve_flood
from faucet import valve_host
from faucet import valve_of
from faucet import valve_packet
from faucet import valve_route
from faucet import valve_util

from faucet.port import STACK_STATE_INIT, STACK_STATE_UP, STACK_STATE_DOWN
from faucet.vlan import NullVLAN


class ValveLogger:
    """Logger for a Valve that adds DP ID."""

    def __init__(self, logger, dp_id, dp_name):
        self.logger = logger
        self.dp_id = dp_id
        self.dp_name = dp_name

    def _dpid_prefix(self, log_msg):
        """Add DP ID prefix to log message."""
        return ' '.join((valve_util.dpid_log(self.dp_id), self.dp_name, log_msg))

    def debug(self, log_msg):
        """Log debug level message."""
        self.logger.debug(self._dpid_prefix(log_msg))

    def info(self, log_msg):
        """Log info level message."""
        self.logger.info(self._dpid_prefix(log_msg))

    def error(self, log_msg):
        """Log error level message."""
        self.logger.error(self._dpid_prefix(log_msg))

    def warning(self, log_msg):
        """Log warning level message."""
        self.logger.warning(self._dpid_prefix(log_msg))


class Valve:
    """Generates the messages to configure a datapath as a l2 learning switch.

    Vendor specific implementations may require sending configuration flows.
    This can be achieved by inheriting from this class and overwriting the
    function switch_features.
    """

    DEC_TTL = True
    USE_BARRIERS = True
    base_prom_labels = None
    recent_ofmsgs = deque(maxlen=32) # type: ignore
    logger = None
    ofchannel_logger = None
    host_manager = None
    flood_manager = None
    _last_pipeline_flows = [] # type: list
    _route_manager_by_ipv = None
    _last_advertise_sec = None
    _port_highwater = {} # type: dict
    _last_update_metrics_sec = None
    _last_packet_in_sec = 0
    _packet_in_count_sec = 0

    def __init__(self, dp, logname, metrics, notifier):
        self.dp = dp
        self.logname = logname
        self.metrics = metrics
        self.notifier = notifier
        self.dp_init()

    def close_logs(self):
        """Explicitly close any active loggers."""
        if self.logger is not None:
            valve_util.close_logger(self.logger.logger)
        valve_util.close_logger(self.ofchannel_logger)

    def dp_init(self):
        """Initialize datapath state at connection/re/config time."""
        self.close_logs()
        self.logger = ValveLogger(
            logging.getLogger(self.logname + '.valve'), self.dp.dp_id, self.dp.name)
        self.ofchannel_logger = None
        self.base_prom_labels = {
            'dp_id': hex(self.dp.dp_id),
            'dp_name': self.dp.name,
        }
        self._packet_in_count_sec = 0
        self._last_packet_in_sec = 0
        self._last_advertise_sec = 0
        self._route_manager_by_ipv = {}
        self._route_manager_by_eth_type = {}
        self._port_highwater = {}

        self.dp.reset_refs()
        for vlan_vid in list(self.dp.vlans.keys()):
            self._port_highwater[vlan_vid] = {}
            for port_number in list(self.dp.ports.keys()):
                self._port_highwater[vlan_vid][port_number] = 0
        for ipv, route_manager_class in (
                (4, valve_route.ValveIPv4RouteManager),
                (6, valve_route.ValveIPv6RouteManager)):
            fib_table_name = 'ipv%u_fib' % ipv
            if not fib_table_name in self.dp.tables:
                continue
            fib_table = self.dp.tables[fib_table_name]
            route_manager = route_manager_class(
                self.logger, self.dp.arp_neighbor_timeout,
                self.dp.max_hosts_per_resolve_cycle, self.dp.max_host_fib_retry_count,
                self.dp.max_resolve_backoff_time, self.dp.proactive_learn, self.DEC_TTL,
                fib_table, self.dp.tables['vip'], self.dp.tables['eth_src'],
                self.dp.tables['eth_dst'], self.dp.tables['flood'],
                self.dp.highest_priority, self.dp.routers,
                self.dp.group_table_routing, self.dp.groups)
            self._route_manager_by_ipv[route_manager.IPV] = route_manager
            for vlan in list(self.dp.vlans.values()):
                if vlan.faucet_vips_by_ipv(route_manager.IPV):
                    route_manager.active = True
                    self.logger.info('IPv%u routing is active on %s with VIPs %s' % (
                        route_manager.IPV, vlan, vlan.faucet_vips_by_ipv(route_manager.IPV)))
            for eth_type in route_manager.CONTROL_ETH_TYPES:
                self._route_manager_by_eth_type[eth_type] = route_manager
        if self.dp.stack:
            self.flood_manager = valve_flood.ValveFloodStackManager(
                self.dp.tables['flood'], self.dp.tables['eth_src'],
                self.dp.low_priority, self.dp.highest_priority,
                self.dp.group_table, self.dp.groups,
                self.dp.combinatorial_port_flood,
                self.dp.stack, self.dp.stack_ports,
                self.dp.shortest_path_to_root, self.dp.shortest_path_port)
        else:
            self.flood_manager = valve_flood.ValveFloodManager(
                self.dp.tables['flood'], self.dp.tables['eth_src'],
                self.dp.low_priority, self.dp.highest_priority,
                self.dp.group_table, self.dp.groups,
                self.dp.combinatorial_port_flood)
        if self.dp.use_idle_timeout:
            self.host_manager = valve_host.ValveHostFlowRemovedManager(
                self.logger, self.dp.ports, self.dp.vlans,
                self.dp.tables['eth_src'], self.dp.tables['eth_dst'],
                self.dp.timeout, self.dp.learn_jitter, self.dp.learn_ban_timeout,
                self.dp.low_priority, self.dp.highest_priority)
        else:
            self.host_manager = valve_host.ValveHostManager(
                self.logger, self.dp.ports, self.dp.vlans,
                self.dp.tables['eth_src'], self.dp.tables['eth_dst'],
                self.dp.timeout, self.dp.learn_jitter, self.dp.learn_ban_timeout,
                self.dp.low_priority, self.dp.highest_priority)
        table_configs = sorted([
            (table.table_id, str(table.table_config)) for table in self.dp.tables.values()])
        for _, table_config in table_configs:
            self.logger.info(table_config)

    def _notify(self, event_dict):
        """Send an event notification."""
        self.notifier.notify(self.dp.dp_id, self.dp.name, event_dict)

    def switch_features(self, _msg):
        """Send configuration flows necessary for the switch implementation.

        Args:
            msg (OFPSwitchFeatures): msg sent from switch.

        Vendor specific configuration should be implemented here.
        """
        ofmsgs = [
            valve_of.faucet_config(),
            valve_of.faucet_async(
                packet_in=False, notify_flow_removed=False, port_status=False),
            valve_of.desc_stats_request()]
        ofmsgs.extend(self._delete_all_valve_flows())
        return ofmsgs

    def ofchannel_log(self, ofmsgs):
        """Log OpenFlow messages in text format to debugging log."""
        if self.dp is None:
            return
        if self.dp.ofchannel_log is None:
            return
        if self.ofchannel_logger is None:
            self.ofchannel_logger = valve_util.get_logger(
                self.dp.ofchannel_log,
                self.dp.ofchannel_log,
                logging.DEBUG,
                0)
        log_prefix = '%u %s' % (
            len(ofmsgs), valve_util.dpid_log(self.dp.dp_id))
        for i, ofmsg in enumerate(ofmsgs, start=1):
            self.ofchannel_logger.debug(
                '%u/%s %s', i, log_prefix, ofmsg)

    def _delete_all_valve_flows(self):
        """Delete all flows from all FAUCET tables."""
        ofmsgs = []
        ofmsgs.extend(self.dp.wildcard_table.flowdel())
        if self.dp.meters:
            ofmsgs.append(valve_of.meterdel())
        if self.dp.group_table:
            ofmsgs.append(self.dp.groups.delete_all())
        return ofmsgs

    def _delete_all_port_match_flows(self, port):
        """Delete all flows that match an input port from all FAUCET tables."""
        ofmsgs = []
        tables = [self.dp.wildcard_table]
        if self.dp.dp_acls:
            # DP ACL flows live forever.
            port_acl_table = self.dp.tables['port_acl']
            tables = set(self.dp.in_port_tables()) - set([port_acl_table])
        for table in tables:
            ofmsgs.extend(table.flowdel(
                match=table.match(in_port=port.number)))
        return ofmsgs

    @staticmethod
    def _pipeline_flows():
        return []

    def _add_default_drop_flows(self):
        """Add default drop rules on all FAUCET tables."""
        eth_src_table = self.dp.tables['eth_src']
        flood_table = self.dp.tables['flood']

        # default drop on all tables.
        ofmsgs = []
        for table in list(self.dp.tables.values()):
            ofmsgs.append(table.flowdrop(priority=self.dp.lowest_priority))

        # drop broadcast sources
        if self.dp.drop_broadcast_source_address:
            ofmsgs.append(eth_src_table.flowdrop(
                eth_src_table.match(eth_src=valve_of.mac.BROADCAST_STR),
                priority=self.dp.highest_priority))

        # antispoof for FAUCET's MAC address
        # TODO: antispoof for controller IPs on this VLAN, too.
        if self.dp.drop_spoofed_faucet_mac:
            for vlan in list(self.dp.vlans.values()):
                ofmsgs.append(eth_src_table.flowdrop(
                    eth_src_table.match(eth_src=vlan.faucet_mac),
                    priority=self.dp.high_priority))

        ofmsgs.append(flood_table.flowdrop(
            flood_table.match(
                eth_dst=valve_packet.CISCO_SPANNING_GROUP_ADDRESS),
            priority=self.dp.highest_priority))
        ofmsgs.append(flood_table.flowdrop(
            flood_table.match(
                eth_dst=valve_packet.BRIDGE_GROUP_ADDRESS,
                eth_dst_mask=valve_packet.BRIDGE_GROUP_MASK),
            priority=self.dp.highest_priority))

        return ofmsgs

    def _vlan_add_acl(self, vlan):
        ofmsgs = []
        if vlan.acls_in:
            acl_table = self.dp.tables['vlan_acl']
            acl_allow_inst = valve_of.goto_table(self.dp.tables['eth_src'])
            acl_force_port_vlan_inst = valve_of.goto_table(self.dp.tables['eth_dst'])
            ofmsgs = valve_acl.build_acl_ofmsgs(
                vlan.acls_in, acl_table,
                acl_allow_inst, acl_force_port_vlan_inst,
                self.dp.highest_priority, self.dp.meters,
                vlan.acls_in[0].exact_match, vlan_vid=vlan.vid)
        return ofmsgs

    def _add_vlan_flood_flow(self):
        """Add a flow to flood packets for unknown destinations."""
        return [self.dp.tables['eth_dst'].flowmod(
            priority=self.dp.low_priority,
            inst=[valve_of.goto_table(self.dp.tables['flood'])])]

    def _add_packetin_meter(self):
        """Add rate limiting of packet in pps (not supported by many DPs)."""
        if self.dp.packetin_pps:
            return [
                valve_of.controller_pps_meterdel(),
                valve_of.controller_pps_meteradd(pps=self.dp.packetin_pps)]
        return []

    def _add_dp_acls(self):
        """Add dataplane ACLs, if any."""
        ofmsgs = []
        if self.dp.dp_acls:
            port_acl_table = self.dp.tables['port_acl']
            acl_allow_inst = valve_of.goto_table(self.dp.tables['vlan'])
            acl_force_port_vlan_inst = valve_of.goto_table(self.dp.tables['eth_dst'])
            ofmsgs.extend(valve_acl.build_acl_ofmsgs(
                self.dp.dp_acls, port_acl_table,
                acl_allow_inst, acl_force_port_vlan_inst,
                self.dp.highest_priority, self.dp.meters,
                False)) # TODO: exact match support for DP ACLs.
        return ofmsgs

    def _add_non_local_vlan_destination_flow(self):
        """Add flow to handle packets not destined to a local VLAN."""
        return [self.dp.tables['eth_src'].flowmod(
            priority=self.dp.lowest_priority,
            inst=[valve_of.goto_table(self.dp.tables['eth_dst'])])]

    def _add_default_flows(self):
        """Configure datapath with necessary default tables and rules."""
        ofmsgs = []
        ofmsgs.extend(self._delete_all_valve_flows())
        ofmsgs.extend(self._add_packetin_meter())
        if self.dp.meters:
            for meter in list(self.dp.meters.values()):
                ofmsgs.append(meter.entry_msg)
        ofmsgs.extend(self._add_default_drop_flows())
        ofmsgs.extend(self._add_vlan_flood_flow())
        ofmsgs.extend(self._add_dp_acls())
        ofmsgs.extend(self._add_non_local_vlan_destination_flow())
        return ofmsgs

    def _add_vlan(self, vlan):
        """Configure a VLAN."""
        ofmsgs = []
        self.logger.info('Configuring %s' % vlan)
        # add ACL rules
        ofmsgs.extend(self._vlan_add_acl(vlan))
        # add controller IPs if configured.
        for ipv in vlan.ipvs():
            route_manager = self._route_manager_by_ipv[ipv]
            ofmsgs.extend(self._add_faucet_vips(
                route_manager, vlan, vlan.faucet_vips_by_ipv(ipv)))
        # install eth_dst_table flood ofmsgs
        ofmsgs.extend(self.flood_manager.build_flood_rules(vlan))
        # add learn rule for this VLAN.
        eth_src_table = self.dp.tables['eth_src']
        ofmsgs.append(eth_src_table.flowcontroller(
            eth_src_table.match(vlan=vlan),
            priority=self.dp.low_priority,
            inst=[valve_of.goto_table(self.dp.tables['eth_dst'])]))
        return ofmsgs

    def _del_vlan(self, vlan):
        """Delete a configured VLAN."""
        table = self.dp.wildcard_table
        ofmsgs = table.flowdel(match=table.match(vlan=vlan))
        self.logger.info('Delete VLAN %s' % vlan)
        return ofmsgs

    def _add_ports_and_vlans(self, discovered_up_port_nos):
        """Add all configured and discovered ports and VLANs."""
        all_configured_port_nos = set()

        for port in self.dp.stack_ports:
            all_configured_port_nos.add(port.number)

        for port in self.dp.output_only_ports:
            all_configured_port_nos.add(port.number)

        ofmsgs = []
        for vlan in list(self.dp.vlans.values()):
            vlan_ports = vlan.get_ports()
            if vlan_ports:
                for port in vlan_ports:
                    all_configured_port_nos.add(port.number)
                ofmsgs.extend(self._add_vlan(vlan))
            vlan.reset_caches()

        ports_status = defaultdict(bool)
        for port_no in discovered_up_port_nos:
            if port_no in all_configured_port_nos:
                ports_status[port_no] = True
        self._notify({'PORTS_STATUS': ports_status})

        all_up_port_nos = set()
        for port_no in all_configured_port_nos:
            if ports_status[port_no]:
                self._set_port_status(port_no, True)
                all_up_port_nos.add(port_no)
            else:
                self._set_port_status(port_no, False)

        ofmsgs.extend(
            self.ports_add(
                all_up_port_nos, cold_start=True, log_msg='configured'))
        self.dp.dyn_up_ports = set(discovered_up_port_nos)
        return ofmsgs

    def ofdescstats_handler(self, body):
        """Handle OF DP description."""
        self.metrics.of_dp_desc_stats.labels( # pylint: disable=no-member
            **dict(self.base_prom_labels,
                   mfr_desc=valve_util.utf8_decode(body.mfr_desc),
                   hw_desc=valve_util.utf8_decode(body.hw_desc),
                   sw_desc=valve_util.utf8_decode(body.sw_desc),
                   serial_num=valve_util.utf8_decode(body.serial_num),
                   dp_desc=valve_util.utf8_decode(body.dp_desc))).set(self.dp.dp_id)

    def _set_port_status(self, port_no, port_status):
        """Set port operational status."""
        port_labels = dict(self.base_prom_labels, port=port_no)
        self.metrics.port_status.labels( # pylint: disable=no-member
            **port_labels).set(port_status)
        if port_status:
            self.dp.dyn_up_ports.add(port_no)
        else:
            self.dp.dyn_up_ports -= set([port_no])

    def port_status_handler(self, port_no, reason, state):
        """Return OpenFlow messages responding to port operational status change."""

        def _decode_port_status(reason):
            """Humanize the port status reason code."""
            port_status_codes = {
                valve_of.ofp.OFPPR_ADD: 'ADD',
                valve_of.ofp.OFPPR_DELETE: 'DELETE',
                valve_of.ofp.OFPPR_MODIFY: 'MODIFY'
            }
            return port_status_codes.get(reason, 'UNKNOWN')

        port_status = valve_of.port_status_from_state(state)
        self._notify(
            {'PORT_CHANGE': {
                'port_no': port_no,
                'reason': _decode_port_status(reason),
                'state': state,
                'status': port_status}})
        ofmsgs = []
        self._set_port_status(port_no, port_status)
        if not self.port_no_valid(port_no):
            return ofmsgs
        port = self.dp.ports[port_no]
        if not port.opstatus_reconf:
            return ofmsgs
        if reason == valve_of.ofp.OFPPR_ADD:
            ofmsgs = self.port_add(port_no)
        elif reason == valve_of.ofp.OFPPR_DELETE:
            ofmsgs = self.port_delete(port_no)
        elif reason == valve_of.ofp.OFPPR_MODIFY:
            ofmsgs.extend(self.port_delete(port_no))
            if port_status:
                ofmsgs.extend(self.port_add(port_no))
        else:
            self.logger.warning('Unhandled port status %s/state %s for %s' % (
                reason, state, port))
        return ofmsgs

    def advertise(self, now):
        """Called periodically to advertise services (eg. IPv6 RAs)."""
        ofmsgs = []
        if (self.dp.advertise_interval and
                now - self._last_advertise_sec > self.dp.advertise_interval):
            for vlan in list(self.dp.vlans.values()):
                for route_manager in list(self._route_manager_by_ipv.values()):
                    ofmsgs.extend(route_manager.advertise(vlan))
            self._last_advertise_sec = now
        return ofmsgs

    def _send_lldp_beacon_on_port(self, port, now):
        chassis_id = str(self.dp.faucet_dp_mac)
        ttl = self.dp.lldp_beacon['send_interval'] * 3
        lldp_beacon = port.lldp_beacon
        chassis_id = str(self.dp.faucet_dp_mac)
        org_tlvs = [
            (tlv['oui'], tlv['subtype'], tlv['info'])
            for tlv in lldp_beacon['org_tlvs']]
        org_tlvs.extend(valve_packet.faucet_lldp_tlvs(self.dp))
        org_tlvs.extend(valve_packet.faucet_lldp_stack_state_tlvs(self.dp, port))
        system_name = lldp_beacon['system_name']
        if not system_name:
            system_name = self.dp.lldp_beacon['system_name']
        lldp_beacon_pkt = valve_packet.lldp_beacon(
            self.dp.faucet_dp_mac,
            chassis_id, port.number, ttl,
            org_tlvs=org_tlvs,
            system_name=system_name,
            port_descr=lldp_beacon['port_descr'])
        port.dyn_last_lldp_beacon_time = now
        return valve_of.packetout(port.number, lldp_beacon_pkt.data)

    def _lldp_beacon_ports(self, now):
        """Return list of ports to send LLDP packets; stacked ports always send LLDP."""
        priority_ports = {
            port for port in self.dp.stack_ports
            if port.running() and port.lldp_beacon_enabled()}
        cutoff_beacon_time = now - self.dp.lldp_beacon['send_interval']
        nonpriority_ports = {
            port for port in self.dp.lldp_beacon_ports
            if port.running() and (
                port.dyn_last_lldp_beacon_time is None or
                port.dyn_last_lldp_beacon_time < cutoff_beacon_time)}
        nonpriority_ports -= priority_ports
        send_ports = list(priority_ports)
        send_ports.extend(list(nonpriority_ports)[:self.dp.lldp_beacon['max_per_interval']])
        random.shuffle(send_ports)
        return send_ports

    def send_lldp_beacons(self, now):
        """Called periodically to send LLDP beacon packets."""
        # TODO: the beacon service is specifically NOT to support conventional R/STP.
        # It is intended to facilitate physical troubleshooting (e.g.
        # a standard cable tester can display OF port information).
        # It is used also by stacking to verify stacking links.
        # TODO: in the stacking case, provide an authentication scheme for the probes
        # so they cannot be forged.
        if not self.dp.lldp_beacon:
            return []
        send_ports = self._lldp_beacon_ports(now)
        self.logger.debug('sending LLDP beacons on ports %s' % send_ports)
        ofmsgs = [self._send_lldp_beacon_on_port(port, now) for port in send_ports]
        return ofmsgs

    def _update_stack_link_state(self, port, now):
        if port.is_stack_admin_down():
            return
        stack_probe_info = port.dyn_stack_probe_info
        last_seen_lldp_time = stack_probe_info.get('last_seen_lldp_time', None)
        if last_seen_lldp_time is None:
            return
        next_state = None
        remote_dp = port.stack['dp']
        stack_correct = stack_probe_info['stack_correct']
        remote_port_state = stack_probe_info['remote_port_state']
        send_interval = remote_dp.lldp_beacon['send_interval']
        num_lost_lldp = round((now - last_seen_lldp_time) / send_interval)
        if not stack_correct:
            if not port.is_stack_down():
                next_state = port.stack_down
                self.logger.error('Stack %s DOWN, incorrect cabling' % port)
        elif num_lost_lldp > port.max_lldp_lost:
            if not port.is_stack_down():
                next_state = port.stack_down
                self.logger.error(
                    'Stack %s DOWN, too many (%u) packets lost' % (port, num_lost_lldp))
        elif port.is_stack_down() and not port.is_stack_init():
            next_state = port.stack_init
            self.logger.info('Stack %s INIT' % port)
        elif (port.is_stack_init() and
              remote_port_state in frozenset([STACK_STATE_UP, STACK_STATE_INIT])):
            next_state = port.stack_up
            self.logger.info('Stack %s UP' % port)
        elif port.is_stack_up() and remote_port_state == STACK_STATE_DOWN:
            next_state = port.stack_down
            self.logger.error('Stack %s DOWN, remote port is down' % port)
        if next_state is None:
            return
        next_state()
        port_labels = dict(self.base_prom_labels, port=port.number)
        self.metrics.port_stack_state.labels( # pylint: disable=no-member
            **port_labels).set(port.dyn_stack_current_state)
        port_stack_up = port.is_stack_up()
        self.flood_manager.update_stack_topo(port_stack_up, self.dp, port)

    def update_stack_link_states(self, now):
        """Called periodically to verify the state of stack ports."""
        for port in self.dp.stack_ports:
            self._update_stack_link_state(port, now)

    def datapath_connect(self, now, discovered_up_ports):
        """Handle Ryu datapath connection event and provision pipeline.

        Args:
            now (float): current epoch time.
            discovered_up_ports (list): datapath port numbers that are up.
        Returns:
            list: OpenFlow messages to send to datapath.
        """
        self.logger.info('Cold start configuring DP')
        self._notify(
            {'DP_CHANGE': {
                'reason': 'cold_start'}})
        ofmsgs = []
        ofmsgs.extend(self._add_default_flows())
        ofmsgs.extend(self._add_ports_and_vlans(discovered_up_ports))
        ofmsgs.append(
            valve_of.faucet_async(
                packet_in=True,
                port_status=True,
                notify_flow_removed=self.dp.use_idle_timeout))
        self.dp.dyn_last_coldstart_time = now
        self.dp.dyn_running = True
        self.metrics.of_dp_connections.labels( # pylint: disable=no-member
            **self.base_prom_labels).inc()
        self.metrics.dp_status.labels( # pylint: disable=no-member
            **self.base_prom_labels).set(1)
        return ofmsgs

    def datapath_disconnect(self):
        """Handle Ryu datapath disconnection event."""
        self.logger.warning('datapath down')
        self._notify(
            {'DP_CHANGE': {
                'reason': 'disconnect'}})
        self.dp.dyn_running = False
        self.metrics.of_dp_disconnections.labels( # pylint: disable=no-member
            **self.base_prom_labels).inc()
        self.metrics.dp_status.labels( # pylint: disable=no-member
            **self.base_prom_labels).set(0)

    def _port_add_acl(self, port, cold_start=False):
        ofmsgs = []
        acl_table = self.dp.tables['port_acl']
        in_port_match = acl_table.match(in_port=port.number)
        if cold_start:
            ofmsgs.extend(acl_table.flowdel(in_port_match))
        acl_allow_inst = valve_of.goto_table(self.dp.tables['vlan'])
        acl_force_port_vlan_inst = valve_of.goto_table(self.dp.tables['eth_dst'])
        if port.acls_in:
            ofmsgs.extend(valve_acl.build_acl_ofmsgs(
                port.acls_in, acl_table,
                acl_allow_inst, acl_force_port_vlan_inst,
                self.dp.highest_priority, self.dp.meters,
                port.acls_in[0].exact_match, port_num=port.number))
        else:
            ofmsgs.append(acl_table.flowmod(
                in_port_match,
                priority=self.dp.highest_priority,
                inst=[acl_allow_inst]))
        return ofmsgs

    def _port_add_vlan_rules(self, port, vlan_vid, vlan_inst):
        vlan_table = self.dp.tables['vlan']
        ofmsgs = []
        ofmsgs.append(vlan_table.flowmod(
            vlan_table.match(in_port=port.number, vlan=vlan_vid),
            priority=self.dp.low_priority,
            inst=vlan_inst))
        return ofmsgs

    def _port_add_vlan_untagged(self, port, vlan, forwarding_table, mirror_act):
        push_vlan_act = mirror_act + valve_of.push_vlan_act(vlan.vid)
        push_vlan_inst = [
            valve_of.apply_actions(push_vlan_act),
            valve_of.goto_table(forwarding_table)
        ]
        return self._port_add_vlan_rules(port, NullVLAN(), push_vlan_inst)

    def _port_add_vlan_tagged(self, port, vlan, forwarding_table, mirror_act):
        vlan_inst = [
            valve_of.goto_table(forwarding_table)
        ]
        if mirror_act:
            vlan_inst = [valve_of.apply_actions(mirror_act)] + vlan_inst
        return self._port_add_vlan_rules(port, vlan, vlan_inst)

    def _find_forwarding_table(self, vlan):
        if vlan.acls_in:
            return self.dp.tables['vlan_acl']
        return self.dp.tables['eth_src']

    def _port_add_vlans(self, port, mirror_act):
        ofmsgs = []
        for vlan in port.tagged_vlans:
            ofmsgs.extend(self._port_add_vlan_tagged(
                port, vlan, self._find_forwarding_table(vlan), mirror_act))
        if port.native_vlan is not None:
            ofmsgs.extend(self._port_add_vlan_untagged(
                port, port.native_vlan, self._find_forwarding_table(port.native_vlan), mirror_act))
        return ofmsgs

    def _port_delete_flows_state(self, port):
        """Delete flows/state for a port."""
        ofmsgs = []
        ofmsgs.extend(self._delete_all_port_match_flows(port))
        ofmsgs.extend(self.dp.tables['eth_dst'].flowdel(out_port=port.number))
        if port.permanent_learn:
            eth_src_table = self.dp.tables['eth_src']
            for entry in port.hosts():
                ofmsgs.extend(eth_src_table.flowdel(
                    match=eth_src_table.match(eth_src=entry.eth_src)))
        for vlan in port.vlans():
            vlan.clear_cache_hosts_on_port(port)
        return ofmsgs

    def ports_add(self, port_nums, cold_start=False, log_msg='up'):
        """Handle the addition of ports.

        Args:
            port_num (list): list of port numbers.
            cold_start (bool): True if configuring datapath from scratch.
        Returns:
            list: OpenFlow messages, if any.
        """
        ofmsgs = []
        vlans_with_ports_added = set()
        eth_src_table = self.dp.tables['eth_src']
        vlan_table = self.dp.tables['vlan']

        for port_num in port_nums:
            if port_num not in self.dp.ports:
                self.logger.info(
                    'Ignoring port:%u not present in configuration file' % port_num)
                continue

            port = self.dp.ports[port_num]
            port.dyn_phys_up = True
            self.logger.info('%s %s' % (port, log_msg))

            if not port.running():
                continue

            if port.output_only:
                ofmsgs.append(vlan_table.flowdrop(
                    match=vlan_table.match(in_port=port_num),
                    priority=self.dp.highest_priority))
                continue

            if port.receive_lldp:
                ofmsgs.append(vlan_table.flowcontroller(
                    match=vlan_table.match(
                        in_port=port_num,
                        eth_dst=valve_packet.LLDP_MAC_NEAREST_BRIDGE,
                        eth_dst_mask=valve_packet.BRIDGE_GROUP_MASK,
                        eth_type=valve_of.ether.ETH_TYPE_LLDP),
                    priority=self.dp.highest_priority,
                    max_len=128))

            if port.lacp:
                ofmsgs.extend(self.lacp_down(port))

            if port.override_output_port:
                ofmsgs.append(self.dp.tables['eth_src'].flowmod(
                    match=self.dp.tables['eth_src'].match(
                        in_port=port_num),
                    priority=self.dp.low_priority + 1,
                    inst=[valve_of.apply_actions([
                        valve_of.output_controller(),
                        valve_of.output_port(port.override_output_port.number)])]))

            if not self.dp.dp_acls:
                acl_ofmsgs = self._port_add_acl(port)
                ofmsgs.extend(acl_ofmsgs)

            port_vlans = port.vlans()

            # If this is a stacking port, accept all VLANs (came from another FAUCET)
            if port.stack is not None:
                # Actual stack traffic will have VLAN tags.
                ofmsgs.append(vlan_table.flowdrop(
                    match=vlan_table.match(
                        in_port=port_num,
                        vlan=NullVLAN()),
                    priority=self.dp.low_priority+1))
                ofmsgs.append(vlan_table.flowmod(
                    match=vlan_table.match(in_port=port_num),
                    priority=self.dp.low_priority,
                    inst=[valve_of.goto_table(eth_src_table)]))
                port_vlans = list(self.dp.vlans.values())
            else:
                mirror_act = port.mirror_actions()
                # Add port/to VLAN rules.
                ofmsgs.extend(self._port_add_vlans(port, mirror_act))

            for vlan in port_vlans:
                vlans_with_ports_added.add(vlan)

        # Only update flooding rules if not cold starting.
        if not cold_start:
            for vlan in vlans_with_ports_added:
                ofmsgs.extend(self.flood_manager.build_flood_rules(vlan))
        return ofmsgs

    def port_add(self, port_num):
        """Handle addition of a single port.

        Args:
            port_num (list): list of port numbers.
        Returns:
            list: OpenFlow messages, if any.
        """
        return self.ports_add([port_num])

    def ports_delete(self, port_nums, log_msg='down'):
        """Handle the deletion of ports.

        Args:
            port_nums (list): list of port numbers.
        Returns:
            list: OpenFlow messages, if any.
        """
        ofmsgs = []
        vlans_with_deleted_ports = set()

        for port_num in port_nums:
            if port_num not in self.dp.ports:
                continue
            port = self.dp.ports[port_num]
            port.dyn_phys_up = False
            self.logger.info('%s %s' % (port, log_msg))

            if not port.output_only:
                if port.lacp:
                    ofmsgs.extend(self.lacp_down(port))
                else:
                    ofmsgs.extend(self._port_delete_flows_state(port))
                for vlan in port.vlans():
                    vlans_with_deleted_ports.add(vlan)

        for vlan in vlans_with_deleted_ports:
            ofmsgs.extend(self.flood_manager.build_flood_rules(
                vlan, modify=True))

        return ofmsgs

    def port_delete(self, port_num):
        """Return flow messages that delete port from pipeline."""
        return self.ports_delete([port_num])

    def lacp_down(self, port):
        """Return OpenFlow messages when LACP is down on a port."""
        port.dyn_lacp_up = 0
        vlan_table = self.dp.tables['vlan']
        ofmsgs = []
        ofmsgs.extend(self._port_delete_flows_state(port))
        ofmsgs.append(vlan_table.flowdrop(
            match=vlan_table.match(in_port=port.number),
            priority=self.dp.high_priority))
        ofmsgs.append(vlan_table.flowcontroller(
            vlan_table.match(
                in_port=port.number,
                eth_type=valve_of.ether.ETH_TYPE_SLOW,
                eth_dst=valve_packet.SLOW_PROTOCOL_MULTICAST),
            priority=self.dp.highest_priority,
            max_len=128))
        self.metrics.port_lacp_status.labels( # pylint: disable=no-member
            **dict(self.base_prom_labels, port=port.number)).set(0)
        return ofmsgs

    def lacp_up(self, port):
        """Return OpenFlow messages when LACP is up on a port."""
        vlan_table = self.dp.tables['vlan']
        ofmsgs = []
        ofmsgs.extend(vlan_table.flowdel(
            match=vlan_table.match(in_port=port.number),
            priority=self.dp.high_priority, strict=True))
        self.metrics.port_lacp_status.labels( # pylint: disable=no-member
            **dict(self.base_prom_labels, port=port.number)).set(1)
        return ofmsgs

    def lacp_handler(self, now, pkt_meta):
        """Handle a LACP packet.

        We are a currently a passive, non-aggregateable LACP partner.

        Args:
            now (float): current epoch time.
            pkt_meta (PacketMeta): packet for control plane.
        Returns:
            list: OpenFlow messages, if any.
        """
        # TODO: ensure config consistent between LAG ports.
        ofmsgs = []
        if (pkt_meta.eth_dst == valve_packet.SLOW_PROTOCOL_MULTICAST and
                pkt_meta.eth_type == valve_of.ether.ETH_TYPE_SLOW and
                pkt_meta.port.lacp):
            pkt_meta.reparse_all()
            lacp_pkt = valve_packet.parse_lacp_pkt(pkt_meta.pkt)
            if lacp_pkt:
                last_lacp_up = pkt_meta.port.dyn_lacp_up
                pkt_meta.port.dyn_last_lacp_pkt = lacp_pkt
                pkt_meta.port.dyn_lacp_up = lacp_pkt.actor_state_synchronization
                pkt_meta.port.dyn_lacp_updated_time = now
                if last_lacp_up != pkt_meta.port.dyn_lacp_up:
                    self.logger.info('LACP state change from %s to %s on %s to %s LAG %u' % (
                        last_lacp_up, pkt_meta.port.dyn_lacp_up, pkt_meta.port,
                        lacp_pkt.actor_system, pkt_meta.port.lacp))
                    if pkt_meta.port.dyn_lacp_up:
                        ofmsgs.extend(self.lacp_up(pkt_meta.port))
                pkt = valve_packet.lacp_reqreply(
                    self.dp.faucet_dp_mac,
                    self.dp.faucet_dp_mac, pkt_meta.port.lacp, pkt_meta.port.number,
                    lacp_pkt.actor_system, lacp_pkt.actor_key, lacp_pkt.actor_port,
                    lacp_pkt.actor_system_priority, lacp_pkt.actor_port_priority,
                    lacp_pkt.actor_state_defaulted,
                    lacp_pkt.actor_state_expired,
                    lacp_pkt.actor_state_timeout,
                    lacp_pkt.actor_state_collecting,
                    lacp_pkt.actor_state_distributing,
                    lacp_pkt.actor_state_aggregation,
                    lacp_pkt.actor_state_synchronization,
                    lacp_pkt.actor_state_activity)
                ofmsgs.append(valve_of.packetout(pkt_meta.port.number, pkt.data))
        return ofmsgs

    @staticmethod
    def _get_tlvs_by_type(lldp_pkt, tlv_type):
        return [tlv for tlv in lldp_pkt.tlvs if tlv.tlv_type == tlv_type]

    @staticmethod
    def _tlvs_by_subtype(tlvs, subtype):
        return [tlv for tlv in tlvs if tlv.subtype == subtype]

    def _get_faucet_tlvs(self, lldp_pkt):
        return [tlv for tlv in self._get_tlvs_by_type(
            lldp_pkt, valve_packet.lldp.LLDP_TLV_ORGANIZATIONALLY_SPECIFIC)
                if tlv.oui == valve_packet.faucet_oui(self.dp.faucet_dp_mac)]

    def _parse_faucet_lldp(self, lldp_pkt):
        remote_dp_id = None
        remote_dp_name = None
        remote_port_id = None
        remote_port_state = None

        faucet_tlvs = self._get_faucet_tlvs(lldp_pkt)
        if faucet_tlvs:
            dp_id_tlvs = self._tlvs_by_subtype(
                faucet_tlvs, valve_packet.LLDP_FAUCET_DP_ID)
            dp_name_tlvs = self._get_tlvs_by_type(
                lldp_pkt, valve_packet.lldp.LLDP_TLV_SYSTEM_NAME)
            port_id_tlvs = self._get_tlvs_by_type(
                lldp_pkt, valve_packet.lldp.LLDP_TLV_PORT_ID)
            port_state_tlvs = self._tlvs_by_subtype(
                faucet_tlvs, valve_packet.LLDP_FAUCET_STACK_STATE)
            try:
                remote_dp_id = int(dp_id_tlvs[0].info)
                remote_port_id = int(port_id_tlvs[0].port_id)
                remote_port_state = int(port_state_tlvs[0].info)
                remote_dp_name = valve_util.utf8_decode(
                    dp_name_tlvs[0].system_name)
            except ValueError:
                pass
        return (remote_dp_id, remote_dp_name, remote_port_id, remote_port_state)

    def lldp_handler(self, now, pkt_meta):
        """Handle an LLDP packet.

        Args:
            pkt_meta (PacketMeta): packet for control plane.
        """
        if pkt_meta.eth_type != valve_of.ether.ETH_TYPE_LLDP:
            return
        pkt_meta.reparse_all()
        lldp_pkt = valve_packet.parse_lldp(pkt_meta.pkt)
        if not lldp_pkt:
            return

        port = pkt_meta.port
        (remote_dp_id, remote_dp_name,
         remote_port_id, remote_port_state) = self._parse_faucet_lldp(lldp_pkt)

        if remote_dp_id and remote_port_id:
            self.logger.info('FAUCET LLDP from %s (remote %s, port %u)' % (
                pkt_meta.port, valve_util.dpid_log(remote_dp_id), remote_port_id))
            if port.stack:
                remote_dp = port.stack['dp']
                remote_port = port.stack['port']
                stack_correct = True
                self.metrics.stack_probes_received.labels( # pylint: disable=no-member
                    **self.base_prom_labels).inc()
                if (remote_dp_id != remote_dp.dp_id or
                        remote_dp_name != remote_dp.name or
                        remote_port_id != remote_port.number):
                    self.logger.error(
                        'Stack %s cabling incorrect, expected %s:%s:%u, actual %s:%s:%u' % (
                            port,
                            valve_util.dpid_log(remote_dp.dp_id),
                            remote_dp.name,
                            remote_port.number,
                            valve_util.dpid_log(remote_dp_id),
                            remote_dp_name,
                            remote_port_id))
                    stack_correct = False
                    self.metrics.stack_cabling_errors.labels( # pylint: disable=no-member
                        **self.base_prom_labels).inc()
                port.dyn_stack_probe_info = {
                    'last_seen_lldp_time': now,
                    'stack_correct': stack_correct,
                    'remote_dp_id': remote_dp_id,
                    'remote_dp_name': remote_dp_name,
                    'remote_port_id': remote_port_id,
                    'remote_port_state': remote_port_state
                }
                self._update_stack_link_state(port, now)

        self.logger.debug('LLDP from %s: %s' % (pkt_meta.port, str(lldp_pkt)))

    @staticmethod
    def _control_plane_handler(now, pkt_meta, route_manager):
        """Handle a packet probably destined to FAUCET's route managers.

        For example, next hop resolution or ICMP echo requests.

        Args:
            pkt_meta (PacketMeta): packet for control plane.
            route_manager (ValveRouteManager): route manager for this eth_type.
        Returns:
            list: OpenFlow messages, if any.
        """
        if (pkt_meta.eth_dst == pkt_meta.vlan.faucet_mac or
                not valve_packet.mac_addr_is_unicast(pkt_meta.eth_dst)):
            return route_manager.control_plane_handler(now, pkt_meta)
        return []

    def rate_limit_packet_ins(self, now):
        """Return True if too many packet ins this second."""
        if self._last_packet_in_sec != now:
            self._last_packet_in_sec = now
            self._packet_in_count_sec = 0
        self._packet_in_count_sec += 1
        if self.dp.ignore_learn_ins:
            if self._packet_in_count_sec % self.dp.ignore_learn_ins == 0:
                self.metrics.of_ignored_packet_ins.labels( # pylint: disable=no-member
                    **self.base_prom_labels).inc()
                return True
        return False

    def _learn_host(self, now, other_valves, pkt_meta):
        """Possibly learn a host on a port.

        Args:
            valves (list): of all Valves (datapaths).
            pkt_meta (PacketMeta): PacketMeta instance for packet received.
        Returns:
            list: OpenFlow messages, if any.
        """
        learn_port = self.flood_manager.edge_learn_port(
            other_valves, pkt_meta)
        if learn_port is not None:
            learn_flows, previous_port = self.host_manager.learn_host_on_vlan_ports(
                now, learn_port, pkt_meta.vlan, pkt_meta.eth_src,
                last_dp_coldstart_time=self.dp.dyn_last_coldstart_time)
            if learn_flows:
                if pkt_meta.l3_pkt is None:
                    pkt_meta.reparse_ip()
                previous_port_no = None
                port_move_text = ''
                if previous_port is not None:
                    previous_port_no = previous_port.number
                    if pkt_meta.port.number != previous_port_no:
                        port_move_text = ', moved from port %u' % previous_port_no
                self.logger.info(
                    'L2 learned %s (L2 type 0x%4.4x, L3 src %s, L3 dst %s) '
                    'on %s%s on VLAN %u (%u hosts total)' % (
                        pkt_meta.eth_src, pkt_meta.eth_type,
                        pkt_meta.l3_src, pkt_meta.l3_dst, pkt_meta.port, port_move_text,
                        pkt_meta.vlan.vid, pkt_meta.vlan.hosts_count()))
                self._notify(
                    {'L2_LEARN': {
                        'port_no': pkt_meta.port.number,
                        'previous_port_no': previous_port_no,
                        'vid': pkt_meta.vlan.vid,
                        'eth_src': pkt_meta.eth_src,
                        'eth_type': pkt_meta.eth_type,
                        'l3_src_ip': pkt_meta.l3_src,
                        'l3_dst_ip': pkt_meta.l3_dst}})
                return learn_flows
        return []

    def port_no_valid(self, port_no):
        """Return True if supplied port number valid on this datapath."""
        if valve_of.ignore_port(port_no):
            return False
        if port_no not in self.dp.ports:
            self.logger.info('port %u unknown' % port_no)
            return False
        return True

    def parse_rcv_packet(self, in_port, vlan_vid, eth_type, data, orig_len, pkt, eth_pkt):
        """Parse a received packet into a PacketMeta instance.

        Args:
            in_port (int): port packet was received on.
            vlan_vid (int): VLAN VID of port packet was received on.
            eth_type (int): Ethernet type of packet.
            data (bytes): Raw packet data.
            orig_len (int): Original length of packet.
            pkt (ryu.lib.packet.packet): parsed packet received.
            ekt_pkt (ryu.lib.packet.ethernet): parsed Ethernet header.
        Returns:
            PacketMeta instance.
        """
        eth_src = eth_pkt.src
        eth_dst = eth_pkt.dst
        vlan = None
        if vlan_vid is not None:
            vlan = self.dp.vlans[vlan_vid]
        port = self.dp.ports[in_port]
        return valve_packet.PacketMeta(
            data, orig_len, pkt, eth_pkt, port, vlan, eth_src, eth_dst, eth_type)

    def parse_pkt_meta(self, msg):
        """Parse OF packet-in message to PacketMeta."""
        if not self.dp.dyn_running:
            return None
        if self.dp.cookie != msg.cookie:
            return None
        # Drop any packet we didn't specifically ask for
        if msg.reason != valve_of.ofp.OFPR_ACTION:
            return None
        if not msg.match:
            return None
        in_port = msg.match['in_port']
        if not in_port or not self.port_no_valid(in_port):
            return None

        if not msg.data:
            return None
        # Truncate packet in data (OVS > 2.5 does not honor max_len)
        data = msg.data[:valve_of.MAX_PACKET_IN_BYTES]

        # eth/VLAN header only
        pkt, eth_pkt, eth_type, vlan_vid = valve_packet.parse_packet_in_pkt(
            data, max_len=valve_packet.ETH_VLAN_HEADER_SIZE)
        if pkt is None or eth_pkt is None:
            self.logger.info(
                'unparseable packet from port %u' % in_port)
            return None
        if vlan_vid is not None and vlan_vid not in self.dp.vlans:
            self.logger.info(
                'packet for unknown VLAN %u' % vlan_vid)
            return None
        pkt_meta = self.parse_rcv_packet(
            in_port, vlan_vid, eth_type, data, msg.total_len, pkt, eth_pkt)
        if not valve_packet.mac_addr_is_unicast(pkt_meta.eth_src):
            self.logger.info(
                'packet with non-unicast eth_src %s port %u' % (
                    pkt_meta.eth_src, in_port))
            return None
        if self.dp.stack is not None:
            if (not pkt_meta.port.stack and
                    pkt_meta.vlan and
                    pkt_meta.vlan not in pkt_meta.port.tagged_vlans and
                    pkt_meta.vlan != pkt_meta.port.native_vlan):
                self.logger.warning(
                    ('packet from non-stack port number %u is not member of VLAN %u' % (
                        pkt_meta.port.number, pkt_meta.vlan.vid)))
                return None
        return pkt_meta

    def update_config_metrics(self):
        """Update gauge/metrics for configuration."""
        self.metrics.reset_dpid(self.base_prom_labels)
        for table in list(self.dp.tables.values()):
            table_id = table.table_id
            self.metrics.faucet_config_table_names.labels(
                **dict(self.base_prom_labels, table_name=table.name)).set(table_id)

    def update_metrics(self, now, updated_port=None, rate_limited=False):
        """Update Gauge/metrics."""
        if self._last_update_metrics_sec and rate_limited:
            if now - self._last_update_metrics_sec < self.dp.metrics_rate_limit_sec:
                return
        self._last_update_metrics_sec = now

        def _update_vlan(vlan):
            vlan_labels = dict(self.base_prom_labels, vlan=vlan.vid)
            self.metrics.vlan_hosts_learned.labels(
                **vlan_labels).set(vlan.hosts_count())
            self.metrics.vlan_learn_bans.labels(
                **vlan_labels).set(vlan.dyn_learn_ban_count)
            for ipv in vlan.ipvs():
                self.metrics.vlan_neighbors.labels(
                    **dict(vlan_labels, ipv=ipv)).set(vlan.neigh_cache_count_by_ipv(ipv))

        def _update_port(vlan, port):
            port_labels = dict(self.base_prom_labels, port=port.number)
            port_vlan_labels = dict(self.base_prom_labels, vlan=vlan.vid, port=port.number)
            port_vlan_hosts_learned = port.hosts_count(vlans=[vlan])
            self.metrics.port_vlan_hosts_learned.labels(
                **port_vlan_labels).set(port_vlan_hosts_learned)
            self.metrics.port_learn_bans.labels(
                **port_labels).set(port.dyn_learn_ban_count)
            highwater = self._port_highwater[vlan.vid][port.number]
            if highwater > port_vlan_hosts_learned:
                for i in range(port_vlan_hosts_learned, highwater + 1):
                    self.metrics.learned_macs.labels(
                        **dict(port_vlan_labels, n=i)).set(0)
            self._port_highwater[vlan.vid][port.number] = port_vlan_hosts_learned
            port_vlan_hosts = port.hosts(vlans=[vlan])
            assert port_vlan_hosts_learned == len(port_vlan_hosts)
            # TODO: make MAC table updates less expensive.
            for i, entry in enumerate(sorted(port_vlan_hosts)):
                self.metrics.learned_macs.labels(
                    **dict(port_vlan_labels, n=i)).set(entry.eth_src_int)

        if updated_port:
            for vlan in updated_port.vlans():
                _update_vlan(vlan)
                _update_port(vlan, updated_port)
        else:
            for vlan in list(self.dp.vlans.values()):
                _update_vlan(vlan)
                for port in vlan.get_ports():
                    _update_port(vlan, port)

    def rcv_packet(self, now, other_valves, pkt_meta):
        """Handle a packet from the dataplane (eg to re/learn a host).

        The packet may be sent to us also in response to FAUCET
        initiating IPv6 neighbor discovery, or ARP, to resolve
        a nexthop.

        Args:
            other_valves (list): all Valves other than this one.
            pkt_meta (PacketMeta): packet for control plane.
        Return:
            list: OpenFlow messages, if any.
        """
        ofmsgs = []

        self.logger.debug(
            'Packet_in src:%s in_port:%d VLAN:%s' % (
                pkt_meta.eth_src,
                pkt_meta.port.number,
                pkt_meta.vlan))

        if pkt_meta.vlan is None:
            self.metrics.of_non_vlan_packet_ins.labels( # pylint: disable=no-member
                **self.base_prom_labels).inc()
            if pkt_meta.port.lacp:
                lacp_ofmsgs = self.lacp_handler(now, pkt_meta)
                if lacp_ofmsgs:
                    return lacp_ofmsgs
            self.lldp_handler(now, pkt_meta)
            # TODO: verify LLDP message (e.g. org-specific authenticator TLV)
            return ofmsgs

        self.metrics.of_vlan_packet_ins.labels( # pylint: disable=no-member
            **self.base_prom_labels).inc()

        ban_rules = self.host_manager.ban_rules(pkt_meta)
        if ban_rules:
            return ban_rules

        if pkt_meta.eth_type in self._route_manager_by_eth_type:
            route_manager = self._route_manager_by_eth_type[pkt_meta.eth_type]
            if route_manager.active:
                pkt_meta.reparse_ip()
                if pkt_meta.l3_pkt:
                    control_plane_ofmsgs = self._control_plane_handler(now, pkt_meta, route_manager)
                    if control_plane_ofmsgs:
                        ofmsgs.extend(control_plane_ofmsgs)
                    else:
                        ofmsgs.extend(route_manager.add_host_fib_route_from_pkt(now, pkt_meta))

        ofmsgs.extend(self._learn_host(now, other_valves, pkt_meta))
        return ofmsgs

    def _lacp_state_expire(self, vlan, now):
        """Expire controller state for LACP.

        Args:
            vlan (VLAN instance): VLAN with LAGs.
            now (float): current epoch time.
        Return:
            list: OpenFlow messages, if any.
        """
        ofmsgs = []
        for ports in list(vlan.lags().values()):
            lacp_up_ports = [port for port in ports if port.dyn_lacp_up]
            for port in lacp_up_ports:
                lacp_age = now - port.dyn_lacp_updated_time
                if lacp_age > self.dp.lacp_timeout:
                    self.logger.info('LACP on %s expired' % port)
                    ofmsgs.extend(self.lacp_down(port))
        return ofmsgs

    def state_expire(self, now):
        """Expire controller caches/state (e.g. hosts learned).

        Expire state from the host manager only; the switch does its own flow
        expiry.

        Return:
            list: OpenFlow messages, if any.
        """
        ofmsgs = []
        if self.dp.dyn_running:
            for vlan in list(self.dp.vlans.values()):
                expired_hosts = self.host_manager.expire_hosts_from_vlan(vlan, now)
                for entry in expired_hosts:
                    self._notify(
                        {'L2_EXPIRE': {
                            'port_no': entry.port.number,
                            'vid': vlan.vid,
                            'eth_src': entry.eth_src}})
                self._lacp_state_expire(vlan, now)
        return ofmsgs

    def _pipeline_change(self):
        def table_msgs(tfm_flow):
            return {str(x) for x in tfm_flow.body}

        if self._last_pipeline_flows:
            _last_pipeline_flows = table_msgs(self._last_pipeline_flows[0])
            _pipeline_flows = table_msgs(self._pipeline_flows()[0])
            if _last_pipeline_flows != _pipeline_flows:
                self.logger.info('pipeline change: %s' % str(
                    _last_pipeline_flows.difference(_pipeline_flows)))
                return True
        return False

    def _apply_config_changes(self, new_dp, changes):
        """Apply any detected configuration changes.

        Args:
            new_dp: (DP): new dataplane configuration.
            changes (tuple) of:
                deleted_ports (list): deleted port numbers.
                changed_ports (list): changed/added port numbers.
                changed_acl_ports (set): changed ACL only port numbers.
                deleted_vlans (list): deleted VLAN IDs.
                changed_vlans (list): changed/added VLAN IDs.
                all_ports_changed (bool): True if all ports changed.
        Returns:
            tuple:
                cold_start (bool): whether cold starting.
                ofmsgs (list): OpenFlow messages.
        """
        new_dp.dyn_running = True
        (deleted_ports, changed_ports, changed_acl_ports,
         deleted_vlans, changed_vlans, all_ports_changed) = changes

        if self._pipeline_change():
            self.dp = new_dp
            self.dp_init()
            return True, []

        if all_ports_changed:
            self.logger.info('all ports changed')
            self.dp = new_dp
            self.dp_init()
            return True, []

        ofmsgs = []

        if deleted_ports:
            self.logger.info('ports deleted: %s' % deleted_ports)
            ofmsgs.extend(self.ports_delete(deleted_ports))
        if deleted_vlans:
            self.logger.info('VLANs deleted: %s' % deleted_vlans)
            for vid in deleted_vlans:
                vlan = self.dp.vlans[vid]
                ofmsgs.extend(self._del_vlan(vlan))
        if changed_ports:
            self.logger.info('ports changed/added: %s' % changed_ports)
            ofmsgs.extend(self.ports_delete(changed_ports))

        self.dp = new_dp
        self.dp_init()

        if changed_vlans:
            self.logger.info('VLANs changed/added: %s' % changed_vlans)
            for vid in changed_vlans:
                vlan = self.dp.vlans[vid]
                ofmsgs.extend(self._del_vlan(vlan))
                ofmsgs.extend(self._add_vlan(vlan))
        if changed_ports:
            ofmsgs.extend(self.ports_add(changed_ports))
        if changed_acl_ports:
            self.logger.info('ports with ACL only changed: %s' % changed_acl_ports)
            for port_num in changed_acl_ports:
                port = self.dp.ports[port_num]
                ofmsgs.extend(self._port_add_acl(port, cold_start=True))

        return False, ofmsgs

    def reload_config(self, now, new_dp):
        """Reload configuration new_dp.

        Following config changes are currently supported:
            - Port config: support all available configs
                  (e.g. native_vlan, acl_in) & change operations
                  (add, delete, modify) a port
            - ACL config:support any modification, currently reload all
                  rules belonging to an ACL
            - VLAN config: enable, disable routing, etc...

        Args:
            now (float): current epoch time.
            new_dp (DP): new dataplane configuration.
        Returns:
            ofmsgs (list): OpenFlow messages.
        """
        dp_running = self.dp.dyn_running
        up_ports = self.dp.dyn_up_ports
        cold_start, ofmsgs = self._apply_config_changes(
            new_dp, self.dp.get_config_changes(self.logger, new_dp))
        self.dp.dyn_running = dp_running
        restart_type = 'none'
        if self.dp.dyn_running:
            if cold_start:
                # Need to reprovision pipeline on cold start.
                ofmsgs = self.datapath_connect(now, up_ports)
            if ofmsgs:
                if cold_start:
                    self.metrics.faucet_config_reload_cold.labels( # pylint: disable=no-member
                        **self.base_prom_labels).inc()
                    self.logger.info('Cold starting')
                    restart_type = 'cold'
                else:
                    self.metrics.faucet_config_reload_warm.labels( # pylint: disable=no-member
                        **self.base_prom_labels).inc()
                    self.logger.info('Warm starting')
                    restart_type = 'warm'
        else:
            ofmsgs = []
        self._notify({'CONFIG_CHANGE': {'restart_type': restart_type}})
        return ofmsgs

    @staticmethod
    def _add_faucet_vips(route_manager, vlan, faucet_vips):
        ofmsgs = []
        for faucet_vip in faucet_vips:
            ofmsgs.extend(route_manager.add_faucet_vip(vlan, faucet_vip))
        return ofmsgs

    def add_authed_mac(self, port_num, mac):
        """Add authed mac address"""
        # TODO: track dynamic auth state.
        ofmsg = self.dp.tables['port_acl'].flowmod(
            self.dp.tables['port_acl'].match(
                in_port=port_num,
                eth_src=mac),
            priority=self.dp.highest_priority,
            inst=[valve_of.goto_table(self.dp.tables['vlan'])])
        return [ofmsg]

    def add_route(self, vlan, ip_gw, ip_dst):
        """Add route to VLAN routing table."""
        route_manager = self._route_manager_by_ipv[ip_dst.version]
        return route_manager.add_route(vlan, ip_gw, ip_dst)

    def del_route(self, vlan, ip_dst):
        """Delete route from VLAN routing table."""
        route_manager = self._route_manager_by_ipv[ip_dst.version]
        return route_manager.del_route(vlan, ip_dst)

    def resolve_gateways(self, now):
        """Call route managers to re/resolve gateways.

        Returns:
            list: OpenFlow messages, if any.
        """
        if not self.dp.dyn_running:
            return []
        ofmsgs = []
        for vlan in list(self.dp.vlans.values()):
            for route_manager in list(self._route_manager_by_ipv.values()):
                ofmsgs.extend(route_manager.resolve_gateways(vlan, now))
        return ofmsgs

    def oferror(self, msg):
        """Correlate OFError message with flow we sent, if any.

        Args:
            msg (ryu.controller.ofp_event.EventOFPMsgBase): message from datapath.
        """
        self.metrics.of_errors.labels( # pylint: disable=no-member
            **self.base_prom_labels).inc()
        orig_msgs = [orig_msg for orig_msg in self.recent_ofmsgs if orig_msg.xid == msg.xid]
        error_txt = msg
        if orig_msgs:
            error_txt = '%s caused by %s' % (error_txt, orig_msgs[0])
        self.logger.error('OFError %s' % error_txt)

    def prepare_send_flows(self, flow_msgs):
        """Prepare to send flows to datapath.

        Args:
            flow_msgs (list): OpenFlow messages to send.
        """
        reordered_flow_msgs = valve_of.valve_flowreorder(
            flow_msgs, use_barriers=self.USE_BARRIERS)
        self.ofchannel_log(reordered_flow_msgs)
        self.metrics.of_flowmsgs_sent.labels( # pylint: disable=no-member
            **self.base_prom_labels).inc(len(reordered_flow_msgs))
        self.recent_ofmsgs.extend(reordered_flow_msgs)
        return reordered_flow_msgs

    def send_flows(self, ryu_dp, flow_msgs):
        """Send flows to datapath.

        Args:
            ryu_dp (ryu.controller.controller.Datapath): datapath.
            flow_msgs (list): OpenFlow messages to send.
        """
        for flow_msg in self.prepare_send_flows(flow_msgs):
            flow_msg.datapath = ryu_dp
            ryu_dp.send_msg(flow_msg)

    def flow_timeout(self, now, table_id, match):
        """Call flow timeout message handler:

        Args:
            now (float): current epoch time.
            table_id (int): ID of table where flow was installed.
            match (dict): match conditions for expired flow.
        Returns:
            list: OpenFlow messages, if any.
        """
        return self.host_manager.flow_timeout(now, table_id, match)

    def get_config_dict(self):
        """Return datapath config as a dict for experimental API."""
        return self.dp.get_config_dict()


class TfmValve(Valve):
    """Valve implementation that uses OpenFlow send table features messages."""

    PIPELINE_CONF = 'tfm_pipeline.json'

    def _pipeline_flows(self):
        ryu_table_loader = tfm_pipeline.LoadRyuTables(
            self.dp.pipeline_config_dir, self.PIPELINE_CONF)
        return [valve_of.table_features(
            ryu_table_loader.load_tables(self.dp))]

    def _add_default_flows(self):
        ofmsgs = self._pipeline_flows()
        self._last_pipeline_flows = copy.deepcopy(ofmsgs)
        ofmsgs.extend(super(TfmValve, self)._add_default_flows())
        return ofmsgs


class ArubaValve(TfmValve):
    """Valve implementation that uses OpenFlow send table features messages."""

    PIPELINE_CONF = 'aruba_pipeline.json'
    DEC_TTL = False


class CiscoC9KValve(TfmValve):
    """Valve implementation that uses OpenFlow send table features messages."""

    PIPELINE_CONF = 'cisco_c9k_pipeline.json'


class OVSValve(Valve):
    """Valve implementation for OVS."""

    USE_BARRIERS = True


class AlliedTelesis(OVSValve):
    """Valve implementation for AT."""

    DEC_TTL = False


SUPPORTED_HARDWARE = {
    'Allied-Telesis': AlliedTelesis,
    'Aruba': ArubaValve,
    'CiscoC9K': CiscoC9KValve,
    'GenericTFM': TfmValve,
    'Lagopus': Valve,
    'Netronome': Valve,
    'NoviFlow': Valve,
    'Open vSwitch': OVSValve,
    'ZodiacFX': Valve,
}


def valve_factory(dp):
    """Return a Valve object based dp's hardware configuration field.

    Args:
        dp (DP): DP instance with the configuration for this Valve.
    """
    if dp.hardware in SUPPORTED_HARDWARE:
        return SUPPORTED_HARDWARE[dp.hardware]
    return None
