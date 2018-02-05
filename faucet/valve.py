"""Implementation of Valve learning layer 2/3 switch."""

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
# distributed under the License is distributed on an "AS IS" BASIS
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
import time
import queue

from collections import namedtuple

from faucet import tfm_pipeline
from faucet import valve_acl
from faucet import valve_flood
from faucet import valve_host
from faucet import valve_of
from faucet import valve_packet
from faucet import valve_route
from faucet import valve_util


class ValveLogger(object):

    def __init__(self, logger, dp_id):
        self.logger = logger
        self.dp_id = dp_id

    def _dpid_prefix(self, log_msg):
        return ' '.join((valve_util.dpid_log(self.dp_id), log_msg))

    def debug(self, log_msg):
        self.logger.debug(self._dpid_prefix(log_msg))

    def info(self, log_msg):
        self.logger.info(self._dpid_prefix(log_msg))

    def error(self, log_msg):
        self.logger.error(self._dpid_prefix(log_msg))

    def warning(self, log_msg):
        self.logger.warning(self._dpid_prefix(log_msg))


class Valve(object):
    """Generates the messages to configure a datapath as a l2 learning switch.

    Vendor specific implementations may require sending configuration flows.
    This can be achieved by inheriting from this class and overwriting the
    function switch_features.
    """

    DEC_TTL = True
    L3 = False
    base_prom_labels = None
    recent_ofmsgs = queue.Queue(maxsize=32) # type: ignore

    def __init__(self, dp, logname, metrics, notifier):
        self.dp = dp
        self.logger = ValveLogger(
            logging.getLogger(logname + '.valve'), self.dp.dp_id)
        self.metrics = metrics
        self.notifier = notifier
        self.base_prom_labels = {
            'dp_id': hex(self.dp.dp_id),
            'dp_name': self.dp.name,
        }
        self.ofchannel_logger = None
        self._packet_in_count_sec = 0
        self._last_packet_in_sec = 0
        self._last_advertise_sec = 0
        self._route_manager_by_ipv = {}
        self._route_manager_by_eth_type = {}
        for fib_table, route_manager_class in (
                (self.dp.tables['ipv4_fib'], valve_route.ValveIPv4RouteManager),
                (self.dp.tables['ipv6_fib'], valve_route.ValveIPv6RouteManager)):
            route_manager = route_manager_class(
                self.logger, self.dp.arp_neighbor_timeout,
                self.dp.max_hosts_per_resolve_cycle, self.dp.max_host_fib_retry_count,
                self.dp.max_resolve_backoff_time, self.dp.proactive_learn, self.DEC_TTL,
                fib_table, self.dp.tables['vip'], self.dp.tables['eth_src'],
                self.dp.tables['eth_dst'], self.dp.tables['flood'],
                self.dp.highest_priority, self.dp.routers,
                self.dp.group_table_routing, self.dp.groups)
            self._route_manager_by_ipv[route_manager.IPV] = route_manager
            for eth_type in route_manager.CONTROL_ETH_TYPES:
                self._route_manager_by_eth_type[eth_type] = route_manager
        if self.dp.stack:
            self.flood_manager = valve_flood.ValveFloodStackManager(
                self.dp.tables['flood'], self.dp.low_priority,
                self.dp.group_table, self.dp.groups,
                self.dp.stack, self.dp.stack_ports,
                self.dp.shortest_path_to_root, dp.shortest_path_port)
        else:
            self.flood_manager = valve_flood.ValveFloodManager(
                self.dp.tables['flood'], self.dp.low_priority,
                self.dp.group_table, self.dp.groups)
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

    def _notify(self, event_dict):
        """Send an event notification."""
        self.notifier.notify(self.dp.dp_id, self.dp.name, event_dict)

    def switch_features(self, _msg):
        """Send configuration flows necessary for the switch implementation.

        Args:
            msg (OFPSwitchFeatures): msg sent from switch.

        Vendor specific configuration should be implemented here.
        """
        return [valve_of.desc_stats_request()]

    def ofchannel_log(self, ofmsgs):
        """Log OpenFlow messages in text format to debugging log."""
        if (self.dp is not None and
                self.dp.ofchannel_log is not None):
            if self.ofchannel_logger is None:
                self.ofchannel_logger = valve_util.get_logger(
                    self.dp.ofchannel_log,
                    self.dp.ofchannel_log,
                    logging.DEBUG,
                    0)
            for i, ofmsg in enumerate(ofmsgs, start=1):
                log_prefix = '%u/%u %s' % (
                    i, len(ofmsgs), valve_util.dpid_log(self.dp.dp_id))
                self.ofchannel_logger.debug(
                    '%s %s', log_prefix, ofmsg)

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
        for table in self.dp.in_port_tables():
            ofmsgs.extend(table.flowdel(
                match=table.match(in_port=port.number)))
        return ofmsgs

    def _add_default_drop_flows(self):
        """Add default drop rules on all FAUCET tables."""
        vlan_table = self.dp.tables['vlan']
        eth_src_table = self.dp.tables['eth_src']

        # default drop on all tables.
        ofmsgs = []
        for table in self.dp.all_valve_tables():
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

        # drop STP BPDU
        # TODO: compatible bridge loop detection/mitigation.
        if self.dp.drop_bpdu:
            for bpdu_mac in (
                    valve_packet.BRIDGE_GROUP_ADDRESS,
                    valve_packet.CISCO_SPANNING_GROUP_ADDRESS):
                ofmsgs.append(vlan_table.flowdrop(
                    vlan_table.match(eth_dst=bpdu_mac),
                    priority=self.dp.highest_priority))

        # drop LLDP, if configured to.
        if self.dp.drop_lldp:
            ofmsgs.append(vlan_table.flowdrop(
                vlan_table.match(eth_type=valve_of.ether.ETH_TYPE_LLDP),
                priority=self.dp.highest_priority))

        return ofmsgs

    def _vlan_add_acl(self, vlan):
        ofmsgs = []
        if vlan.acls_in:
            acl_table = self.dp.tables['vlan_acl']
            acl_allow_inst = valve_of.goto_table(self.dp.tables['eth_src'])
            ofmsgs = valve_acl.build_acl_ofmsgs(
                vlan.acls_in, acl_table, acl_allow_inst,
                self.dp.highest_priority, self.dp.meters,
                vlan.acls_in[0].exact_match, vlan_vid=vlan.vid)
        return ofmsgs

    def _add_vlan_flood_flow(self):
        """Add a flow to flood packets for unknown destinations."""
        return [self.dp.tables['eth_dst'].flowmod(
            priority=self.dp.low_priority,
            inst=[valve_of.goto_table(self.dp.tables['flood'])])]

    def _add_controller_learn_flow(self):
        """Add a flow for controller to learn/add flows for destinations."""
        return [self.dp.tables['eth_src'].flowcontroller(
            priority=self.dp.low_priority,
            inst=[valve_of.goto_table(self.dp.tables['eth_dst'])])]

    def _add_packetin_meter(self):
        """Add rate limiting of packet in pps (not supported by many DPs)."""
        if self.dp.packetin_pps:
            return [
                valve_of.controller_pps_meterdel(),
                valve_of.controller_pps_meteradd(pps=self.dp.packetin_pps)]
        return []

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
        return ofmsgs

    def _add_vlan(self, vlan):
        """Configure a VLAN."""
        ofmsgs = []
        self.logger.info('Configuring %s' % vlan)
        # install eth_dst_table flood ofmsgs
        ofmsgs.extend(self.flood_manager.build_flood_rules(vlan))
        # add acl rules
        ofmsgs.extend(self._vlan_add_acl(vlan))
        # add controller IPs if configured.
        for ipv in vlan.ipvs():
            route_manager = self._route_manager_by_ipv[ipv]
            ofmsgs.extend(self._add_faucet_vips(
                route_manager, vlan, vlan.faucet_vips_by_ipv(ipv)))
        return ofmsgs

    def _del_vlan(self, vlan):
        """Delete a configured VLAN."""
        ofmsgs = []
        for table in self.dp.vlan_match_tables():
            ofmsgs.extend(table.flowdel(match=table.match(vlan=vlan)))
        self.logger.info('Delete VLAN %s' % vlan)
        return ofmsgs

    def _add_ports_and_vlans(self, discovered_port_nums):
        """Add all configured and discovered ports and VLANs."""
        all_port_nums = set(discovered_port_nums)

        for port in self.dp.stack_ports:
            all_port_nums.add(port.number)

        for port in self.dp.output_only_ports:
            all_port_nums.add(port.number)

        ofmsgs = []
        for vlan in list(self.dp.vlans.values()):
            vlan_ports = vlan.get_ports()
            if vlan_ports:
                for port in vlan_ports:
                    all_port_nums.add(port.number)
                ofmsgs.extend(self._add_vlan(vlan))
            vlan.reset_caches()

        ofmsgs.extend(
            self.ports_add(
                all_port_nums, cold_start=True, log_msg='configured'))
        return ofmsgs

    def ofdescstats_handler(self, body):
        """Handle OF DP description."""
        self.metrics.of_dp_desc_stats.labels( # pylint: disable=no-member
            **dict(self.base_prom_labels,
                   mfr_desc=body.mfr_desc,
                   hw_desc=body.hw_desc,
                   sw_desc=body.sw_desc,
                   serial_num=body.serial_num,
                   dp_desc=body.dp_desc)).set(self.dp.dp_id)

    def port_status_handler(self, port_no, reason, port_status):
        """Return OpenFlow messages responding to port operational status change."""

        def _decode_port_status(reason):
            """Humanize the port status reason code."""
            port_status_codes = {
                valve_of.ofp.OFPPR_ADD: 'ADD',
                valve_of.ofp.OFPPR_DELETE: 'DELETE',
                valve_of.ofp.OFPPR_MODIFY: 'MODIFY'
            }
            return port_status_codes.get(reason, 'UNKNOWN')

        self._notify(
            {'PORT_CHANGE': {
                'port_no': port_no,
                'reason': _decode_port_status(reason),
                'status': port_status}})
        ofmsgs = []
        if not self.port_no_valid(port_no):
            return ofmsgs
        port_labels = dict(self.base_prom_labels, port=port_no)
        self.metrics.port_status.labels( # pylint: disable=no-member
            **port_labels).set(port_status)
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
            self.logger.warning('Unhandled port status %s for %s' % (
                reason, port))
        return ofmsgs

    def advertise(self):
        """Called periodically to advertise services (eg. IPv6 RAs)."""
        ofmsgs = []
        now = time.time()
        if (self.dp.advertise_interval and
                now - self._last_advertise_sec > self.dp.advertise_interval):
            for vlan in list(self.dp.vlans.values()):
                for route_manager in list(self._route_manager_by_ipv.values()):
                    ofmsgs.extend(route_manager.advertise(vlan))
            self._last_advertise_sec = now
        return ofmsgs

    def send_lldp_beacons(self):
        """Called periodically to send LLDP beacon packets."""
        # TODO: the beacon service should be able to send configurable TLVs.
        # TODO: the beacon service is specifically NOT to discover topology.
        # It is intended to facilitate physical troubleshooting (e.g.
        # a standard cable tester can display OF port information)
        # A seperate system will be used to probe link/neighbor activity,
        # addressing issues such as authenticity of the probes.
        ofmsgs = []
        if self.dp.lldp_beacon_ports:
            now = time.time()
            beacons_sent = 0
            cutoff_beacon_time = now - self.dp.lldp_beacon['send_interval']
            ttl = self.dp.lldp_beacon['send_interval'] * 3
            for port in self.dp.lldp_beacon_ports:
                if (port.dyn_last_lldp_beacon_time is None or
                        port.dyn_last_lldp_beacon_time < cutoff_beacon_time):
                    lldp_beacon = port.lldp_beacon
                    chassis_id = str(port.native_vlan.faucet_mac)
                    org_tlvs = []
                    for org_tlv in lldp_beacon['org_tlvs']:
                        org_tlvs.append(
                            (org_tlv['oui'], org_tlv['subtype'], org_tlv['info']))
                    # if the port doesn't have a system name set, default to
                    # using the system name from the dp
                    if lldp_beacon['system_name'] is None:
                        lldp_beacon['system_name'] = self.dp.lldp_beacon['system_name']

                    lldp_beacon_pkt = valve_packet.lldp_beacon(
                        port.native_vlan.faucet_mac,
                        chassis_id, port.number, ttl,
                        org_tlvs=org_tlvs,
                        system_name=lldp_beacon['system_name'],
                        port_descr=lldp_beacon['port_descr'])
                    ofmsgs.append(
                        valve_of.packetout(
                            port.number, lldp_beacon_pkt.data))
                    port.dyn_last_lldp_beacon_time = now
                    beacons_sent += 1
                    if beacons_sent == self.dp.lldp_beacon['max_per_interval']:
                        break
        return ofmsgs

    def datapath_connect(self, discovered_up_port_nums):
        """Handle Ryu datapath connection event and provision pipeline.

        Args:
            discovered_up_port_nums (list): datapath ports that are up as ints.
        Returns:
            list: OpenFlow messages to send to datapath.
        """
        self.logger.info('Cold start configuring DP')
        self._notify(
            {'DP_CHANGE': {
                'reason': 'cold_start'}})
        ofmsgs = []
        ofmsgs.append(valve_of.faucet_config())
        ofmsgs.append(valve_of.faucet_async())
        ofmsgs.extend(self._add_default_flows())
        ofmsgs.extend(self._add_ports_and_vlans(discovered_up_port_nums))
        ofmsgs.extend(self._add_controller_learn_flow())
        self.dp.dyn_last_coldstart_time = time.time()
        self.dp.running = True
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
        self.dp.running = False
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
        if port.acls_in:
            ofmsgs.extend(valve_acl.build_acl_ofmsgs(
                port.acls_in, acl_table, acl_allow_inst,
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
        null_vlan = namedtuple('null_vlan', 'vid')
        null_vlan.vid = valve_of.ofp.OFPVID_NONE
        return self._port_add_vlan_rules(port, null_vlan, push_vlan_inst)

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
            for eth_src in port.hosts():
                ofmsgs.extend(eth_src_table.flowdel(
                    match=eth_src_table.match(eth_src=eth_src)))
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

            # Port has LACP processing enabled.
            if port.lacp:
                ofmsgs.extend(self.lacp_down(port))

            # Add ACL if any.
            acl_ofmsgs = self._port_add_acl(port)
            ofmsgs.extend(acl_ofmsgs)

            port_vlans = port.vlans()

            # If this is a stacking port, accept all VLANs (came from another FAUCET)
            if port.stack is not None:
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
        eth_src_table = self.dp.tables['eth_src']
        ofmsgs = []
        ofmsgs.extend(self._port_delete_flows_state(port))
        ofmsgs.append(eth_src_table.flowdrop(
            match=eth_src_table.match(in_port=port.number),
            priority=self.dp.high_priority))
        ofmsgs.append(eth_src_table.flowcontroller(
            eth_src_table.match(
                in_port=port.number,
                eth_type=valve_of.ether.ETH_TYPE_SLOW,
                eth_dst=valve_packet.SLOW_PROTOCOL_MULTICAST),
            priority=self.dp.highest_priority))
        return ofmsgs

    def lacp_up(self, port):
        """Return OpenFlow messages when LACP is up on a port."""
        eth_src_table = self.dp.tables['eth_src']
        ofmsgs = []
        ofmsgs.extend(eth_src_table.flowdel(
            match=eth_src_table.match(in_port=port.number),
            priority=self.dp.high_priority))
        return ofmsgs

    def lacp_handler(self, pkt_meta):
        """Handle a LACP packet.

        We are a currently a passive, non-aggregateable LACP partner.

        Args:
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
                pkt_meta.port.dyn_lacp_updated_time = time.time()
                if last_lacp_up != pkt_meta.port.dyn_lacp_up:
                    self.logger.info('LACP state change from %s to %s on %s to %s LAG %u' % (
                        last_lacp_up, pkt_meta.port.dyn_lacp_up, pkt_meta.port,
                        lacp_pkt.actor_system, pkt_meta.port.lacp))
                    if pkt_meta.port.dyn_lacp_up:
                        ofmsgs.extend(self.lacp_up(pkt_meta.port))
                pkt = valve_packet.lacp_reqreply(
                    pkt_meta.vlan.faucet_mac,
                    pkt_meta.vlan.faucet_mac, pkt_meta.port.lacp, pkt_meta.port.number,
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

    def _control_plane_handler(self, pkt_meta, route_manager):
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
            return route_manager.control_plane_handler(pkt_meta)
        return []

    def _rate_limit_packet_ins(self):
        """Return True if too many packet ins this second."""
        now_sec = int(time.time())
        if self._last_packet_in_sec != now_sec:
            self._last_packet_in_sec = now_sec
            self._packet_in_count_sec = 0
        self._packet_in_count_sec += 1
        if self.dp.ignore_learn_ins:
            if self._packet_in_count_sec % self.dp.ignore_learn_ins == 0:
                return True
        return False

    def _learn_host(self, other_valves, pkt_meta):
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
            learn_flows = self.host_manager.learn_host_on_vlan_ports(
                learn_port, pkt_meta.vlan, pkt_meta.eth_src,
                last_dp_coldstart_time=self.dp.dyn_last_coldstart_time)
            if learn_flows:
                self.logger.info(
                    'L2 learned %s (L2 type 0x%4.4x, L3 src %s) on %s on VLAN %u (%u hosts total)' % (
                        pkt_meta.eth_src, pkt_meta.eth_type,
                        pkt_meta.l3_src, pkt_meta.port,
                        pkt_meta.vlan.vid, pkt_meta.vlan.hosts_count()))
                self._notify(
                    {'L2_LEARN': {
                        'port_no': pkt_meta.port.number,
                        'vid': pkt_meta.vlan.vid,
                        'eth_src': pkt_meta.eth_src,
                        'eth_type': pkt_meta.eth_type,
                        'l3_src_ip': pkt_meta.l3_src}})
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
        vlan = self.dp.vlans[vlan_vid]
        port = self.dp.ports[in_port]
        return valve_packet.PacketMeta(
            data, orig_len, pkt, eth_pkt, port, vlan, eth_src, eth_dst, eth_type)

    def parse_pkt_meta(self, msg):
        if not self.dp.running:
            return None
        if self.dp.cookie != msg.cookie:
            return None
        # Drop any packet we didn't specifically ask for
        if msg.reason != valve_of.ofp.OFPR_ACTION:
            return None
        in_port = msg.match['in_port']
        if not self.port_no_valid(in_port):
            return None

        # Truncate packet in data (OVS > 2.5 does not honor max_len)
        msg.data = msg.data[:valve_of.MAX_PACKET_IN_BYTES]

        # eth/VLAN header only
        pkt, eth_pkt, vlan_vid, eth_type = valve_packet.parse_packet_in_pkt(
            msg.data, max_len=valve_packet.ETH_VLAN_HEADER_SIZE)
        if vlan_vid is None:
            self.logger.info(
                'packet without VLAN header port %u' % in_port)
            return None
        if pkt is None:
            self.logger.info(
                'unparseable packet from port %u' % in_port)
            return None
        if vlan_vid not in self.dp.vlans:
            self.logger.info(
                'packet for unknown VLAN %u' % vlan_vid)
            return None
        pkt_meta = self.parse_rcv_packet(
            in_port, vlan_vid, eth_type, msg.data, msg.total_len, pkt, eth_pkt)
        if not valve_packet.mac_addr_is_unicast(pkt_meta.eth_src):
            self.logger.info(
                'packet with non-unicast eth_src %s port %u' % (
                    pkt_meta.eth_src, in_port))
            return None
        if self.dp.stack is not None:
            if (not pkt_meta.port.stack and
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
        for table_id, table in list(self.dp.tables_by_id.items()):
            self.metrics.faucet_config_table_names.labels(
                **dict(self.base_prom_labels, table_name=table.name)).set(table_id)

    def update_metrics(self):
        """Update Gauge/metrics."""
        # Clear the exported MAC learning.
        dp_id = hex(self.dp.dp_id)
        for _, label_dict, _ in self.metrics.learned_macs.collect()[0].samples:
            if label_dict['dp_id'] == dp_id:
                self.metrics.learned_macs.labels(
                    **dict(self.base_prom_labels, vlan=label_dict['vlan'],
                           port=label_dict['port'], n=label_dict['n'])).set(0)

        for vlan in list(self.dp.vlans.values()):
            hosts_count = vlan.hosts_count()
            self.metrics.vlan_hosts_learned.labels(
                **dict(self.base_prom_labels, vlan=vlan.vid)).set(
                    hosts_count)
            self.metrics.vlan_learn_bans.labels(
                **dict(self.base_prom_labels, vlan=vlan.vid)).set(
                    vlan.dyn_learn_ban_count)
            for ipv in vlan.ipvs():
                neigh_cache_size = len(vlan.neigh_cache_by_ipv(ipv))
                self.metrics.vlan_neighbors.labels(
                    **dict(self.base_prom_labels, vlan=vlan.vid, ipv=ipv)).set(
                        neigh_cache_size)
            learned_hosts_count = 0
            for port in vlan.get_ports():
                for i, host in enumerate(sorted(port.hosts(vlans=[vlan]))):
                    mac_int = int(host.replace(':', ''), 16)
                    self.metrics.learned_macs.labels(
                        **dict(self.base_prom_labels, vlan=vlan.vid, port=port.number, n=i)).set(
                            mac_int)
                    learned_hosts_count += 1
                self.metrics.port_learn_bans.labels(
                    **dict(self.base_prom_labels, port=port.number)).set(
                        port.dyn_learn_ban_count)

    def rcv_packet(self, other_valves, pkt_meta):
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
            'Packet_in src:%s in_port:%d vid:%s' % (
                pkt_meta.eth_src,
                pkt_meta.port.number,
                pkt_meta.vlan.vid))

        if pkt_meta.port.lacp:
            lacp_ofmsgs = self.lacp_handler(pkt_meta)
            if lacp_ofmsgs:
                return lacp_ofmsgs
            if not pkt_meta.port.dyn_lacp_up:
                return ofmsgs

        ban_rules = self.host_manager.ban_rules(pkt_meta)
        if ban_rules:
            return ban_rules

        pkt_meta.reparse_ip()

        if self.L3 and pkt_meta.l3_pkt and pkt_meta.eth_type in self._route_manager_by_eth_type:
            route_manager = self._route_manager_by_eth_type[pkt_meta.eth_type]
            control_plane_ofmsgs = self._control_plane_handler(pkt_meta, route_manager)
            if control_plane_ofmsgs:
                ofmsgs.extend(control_plane_ofmsgs)
            else:
                ofmsgs.extend(route_manager.add_host_fib_route_from_pkt(pkt_meta))

        if self._rate_limit_packet_ins():
            return ofmsgs

        ofmsgs.extend(self._learn_host(other_valves, pkt_meta))

        return ofmsgs

    def state_expire(self):
        """Expire controller caches/state (e.g. hosts learned).

        Expire state from the host manager only; the switch does its own flow
        expiry.

        Return:
            list: OpenFlow messages, if any.
        """
        ofmsgs = []
        if self.dp.running:
            now = time.time()
            for vlan in list(self.dp.vlans.values()):
                self.host_manager.expire_hosts_from_vlan(vlan, now)
                for _, ports in list(vlan.lags().items()):
                    for port in ports:
                        if port.dyn_lacp_up:
                            lacp_age = now - port.dyn_lacp_updated_time
                            # TODO: LACP timeout configurable.
                            if lacp_age > 10:
                                self.logger.info('LACP on %s expired' % port)
                                ofmsgs.extend(self.lacp_down(port))
        return ofmsgs

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
        (deleted_ports, changed_ports, changed_acl_ports,
         deleted_vlans, changed_vlans, all_ports_changed) = changes
        new_dp.running = True

        if all_ports_changed:
            self.logger.info('all ports changed')
            self.dp = new_dp
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
        self.dp.reset_refs()

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

    def reload_config(self, new_dp):
        """Reload configuration new_dp.

        Following config changes are currently supported:
            - Port config: support all available configs \
                  (e.g. native_vlan, acl_in) & change operations \
                  (add, delete, modify) a port
            - ACL config:support any modification, currently reload all \
                  rules belonging to an ACL
            - VLAN config: enable, disable routing, etc...

        Args:
            new_dp (DP): new dataplane configuration.
        Returns:
            ofmsgs (list): OpenFlow messages.
        """
        cold_start = False
        ofmsgs = []
        if self.dp.running:
            cold_start, ofmsgs = self._apply_config_changes(
                new_dp, self.dp.get_config_changes(self.logger, new_dp))
            if cold_start:
                self.dp = new_dp
                ofmsgs = self.datapath_connect(list(self.dp.ports.keys()))
        else:
            self.logger.info('skipping configuration because datapath not up')
        if ofmsgs:
            if cold_start:
                self.metrics.faucet_config_reload_cold.labels( # pylint: disable=no-member
                    **self.base_prom_labels).inc()
                self.logger.info('Cold starting')
            else:
                self.metrics.faucet_config_reload_warm.labels( # pylint: disable=no-member
                    **self.base_prom_labels).inc()
                self.logger.info('Warm starting')
        return ofmsgs

    def _add_faucet_vips(self, route_manager, vlan, faucet_vips):
        ofmsgs = []
        for faucet_vip in faucet_vips:
            ofmsgs.extend(route_manager.add_faucet_vip(vlan, faucet_vip))
            self.L3 = True
        return ofmsgs

    def add_route(self, vlan, ip_gw, ip_dst):
        """Add route to VLAN routing table."""
        route_manager = self._route_manager_by_ipv[ip_dst.version]
        return route_manager.add_route(vlan, ip_gw, ip_dst)

    def del_route(self, vlan, ip_dst):
        """Delete route from VLAN routing table."""
        route_manager = self._route_manager_by_ipv[ip_dst.version]
        return route_manager.del_route(vlan, ip_dst)

    def resolve_gateways(self):
        """Call route managers to re/resolve gateways.

        Returns:
            list: OpenFlow messages, if any.
        """
        if not self.dp.running:
            return []
        ofmsgs = []
        now = time.time()
        for vlan in list(self.dp.vlans.values()):
            for route_manager in list(self._route_manager_by_ipv.values()):
                ofmsgs.extend(route_manager.resolve_gateways(vlan, now))
        return ofmsgs

    def flow_timeout(self, table_id, match):
        return self.host_manager.flow_timeout(table_id, match)

    def get_config_dict(self):
        return self.dp.get_config_dict()


class TfmValve(Valve):
    """Valve implementation that uses OpenFlow send table features messages."""

    PIPELINE_CONF = 'tfm_pipeline.json'
    SKIP_VALIDATION_TABLES = ()

    def _verify_pipeline_config(self, tfm):
        for tfm_table in tfm.body:
            table = self.dp.tables_by_id[tfm_table.table_id]
            if table.table_id in self.SKIP_VALIDATION_TABLES:
                continue
            if table.restricted_match_types is None:
                continue
            for prop in tfm_table.properties:
                if not (isinstance(prop, valve_of.parser.OFPTableFeaturePropOxm) and prop.type == 8):
                    continue
                tfm_matches = set(sorted([oxm.type for oxm in prop.oxm_ids]))
                if tfm_matches != table.restricted_match_types:
                    self.logger.info(
                        'table %s ID %s match TFM config %s != pipeline %s' % (
                            tfm_table.name, tfm_table.table_id,
                            tfm_matches, table.restricted_match_types))

    def switch_features(self, msg):
        ofmsgs = super(TfmValve, self).switch_features(msg)
        ryu_table_loader = tfm_pipeline.LoadRyuTables(
            self.dp.pipeline_config_dir, self.PIPELINE_CONF)
        self.logger.info('loading pipeline configuration')
        ofmsgs.extend(self._delete_all_valve_flows())
        tfm = valve_of.table_features(ryu_table_loader.load_tables())
        self._verify_pipeline_config(tfm)
        ofmsgs.append(tfm)
        return ofmsgs


class ArubaValve(TfmValve):
    """Valve implementation that uses OpenFlow send table features messages."""

    PIPELINE_CONF = 'aruba_pipeline.json'
    DEC_TTL = False


SUPPORTED_HARDWARE = {
    'Allied-Telesis': Valve,
    'Aruba': ArubaValve,
    'GenericTFM': TfmValve,
    'Lagopus': Valve,
    'Netronome': Valve,
    'NoviFlow': Valve,
    'Open vSwitch': Valve,
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
