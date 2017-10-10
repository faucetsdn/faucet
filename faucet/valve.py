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

from collections import namedtuple

from ryu.lib import mac
from ryu.ofproto import ether
from ryu.ofproto import ofproto_v1_3 as ofp
from ryu.ofproto import ofproto_v1_3_parser as parser

try:
    import tfm_pipeline
    import valve_acl
    import valve_flood
    import valve_host
    import valve_of
    import valve_packet
    import valve_route
    import valve_util
except ImportError:
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

    def __init__(self, dp, logname):
        self.dp = dp
        self.logger = ValveLogger(
            logging.getLogger(logname + '.valve'), self.dp.dp_id)
        self.ofchannel_logger = None
        self._packet_in_count_sec = 0
        self._last_packet_in_sec = 0
        self._last_advertise_sec = 0
        # TODO: functional flow managers require too much state.
        # Should interface with a common composer class.
        self.route_manager_by_ipv = {}
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
            self.route_manager_by_ipv[route_manager.IPV] = route_manager
        self.flood_manager = valve_flood.ValveFloodManager(
            self.dp.tables['flood'], self.dp.low_priority,
            self.dp.stack, self.dp.ports, self.dp.shortest_path_to_root,
            self.dp.group_table, self.dp.groups)
        self.host_manager = valve_host.ValveHostManager(
            self.logger, self.dp.tables['eth_src'], self.dp.tables['eth_dst'],
            self.dp.timeout, self.dp.learn_jitter, self.dp.learn_ban_timeout,
            self.dp.low_priority, self.dp.highest_priority,
            self.dp.use_idle_timeout)

    def switch_features(self, dp_id, msg):
        """Send configuration flows necessary for the switch implementation.

        Arguments:
        dp_id -- the Datapath unique ID (64bit int)
        msg -- OFPSwitchFeatures msg sent from switch.

        Vendor specific configuration should be implemented here.
        """
        return []

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

    def _ignore_dpid(self, dp_id):
        """Return True if this datapath ID is not ours.

        Args:
            dp_id (int): datapath ID
        Returns:
            bool: True if this datapath ID is not ours.
        """
        if dp_id != self.dp.dp_id:
            self.logger.error('Unknown %s' % valve_util.dpid_log(dp_id))
            return True
        return False

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

        # default drop on all tables.
        ofmsgs = []
        for table in self.dp.all_valve_tables():
            ofmsgs.append(table.flowdrop(priority=self.dp.lowest_priority))

        # drop broadcast sources
        if self.dp.drop_broadcast_source_address:
            ofmsgs.append(vlan_table.flowdrop(
                vlan_table.match(eth_src=mac.BROADCAST_STR),
                priority=self.dp.highest_priority))

        # antispoof for FAUCET's MAC address
        # TODO: antispoof for controller IPs on this VLAN, too.
        if self.dp.drop_spoofed_faucet_mac:
            for vlan in list(self.dp.vlans.values()):
                ofmsgs.append(vlan_table.flowdrop(
                    vlan_table.match(eth_src=vlan.faucet_mac),
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
                vlan_table.match(eth_type=ether.ETH_TYPE_LLDP),
                priority=self.dp.highest_priority))

        return ofmsgs

    def _vlan_add_acl(self, vlan):
        ofmsgs = []
        if vlan.acl_in:
            acl_table = self.dp.tables['vlan_acl']
            acl_allow_inst = valve_of.goto_table(self.dp.tables['eth_src'])
            ofmsgs = valve_acl.build_acl_ofmsgs(
                [vlan.acl_in], acl_table, acl_allow_inst,
                self.dp.highest_priority, self.dp.meters,
                vlan_vid=vlan.vid)
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

    def _add_vlan(self, vlan, all_port_nums):
        """Configure a VLAN."""
        ofmsgs = []
        self.logger.info('Configuring %s' % vlan)
        for port in vlan.get_ports():
            all_port_nums.add(port.number)
        # add mirror destination ports.
        for port in vlan.mirror_destination_ports():
            all_port_nums.add(port.number)
        # install eth_dst_table flood ofmsgs
        ofmsgs.extend(self.flood_manager.build_flood_rules(vlan))
        # add acl rules
        ofmsgs.extend(self._vlan_add_acl(vlan))
        # add controller IPs if configured.
        for ipv in vlan.ipvs():
            route_manager = self.route_manager_by_ipv[ipv]
            ofmsgs.extend(self._add_faucet_vips(
                route_manager, vlan, vlan.faucet_vips_by_ipv(ipv)))
        return ofmsgs

    def _del_vlan(self, vlan):
        """Delete a configured VLAN."""
        ofmsgs = []
        vlan_table = self.dp.tables['vlan']
        for table in self.dp.vlan_match_tables():
            if table != vlan_table:
                ofmsgs.extend(table.flowdel(match=table.match(vlan=vlan)))
        self.logger.info('Delete VLAN %s' % vlan)
        return ofmsgs

    def _add_ports_and_vlans(self, discovered_port_nums):
        """Add all configured and discovered ports and VLANs."""
        ofmsgs = []
        all_port_nums = set()

        # add stack ports
        for port in self.dp.stack_ports:
            all_port_nums.add(port.number)

        # add vlan ports
        for vlan in list(self.dp.vlans.values()):
            ofmsgs.extend(self._add_vlan(vlan, all_port_nums))

        # add any ports discovered but not configured
        for port_num in discovered_port_nums:
            if valve_of.ignore_port(port_num):
                continue
            if port_num not in all_port_nums:
                all_port_nums.add(port_num)

        # now configure all ports
        ofmsgs.extend(self.ports_add(
            self.dp.dp_id, all_port_nums, cold_start=True))

        return ofmsgs

    def port_status_handler(self, dp_id, port_no, reason, port_status):
        if reason == ofp.OFPPR_ADD:
            return self.port_add(dp_id, port_no)
        elif reason == ofp.OFPPR_DELETE:
            return self.port_delete(dp_id, port_no)
        elif reason == ofp.OFPPR_MODIFY:
            ofmsgs = []
            ofmsgs.extend(self.port_delete(dp_id, port_no))
            if port_status:
                ofmsgs.extend(self.port_add(dp_id, port_no))
            return ofmsgs
        self.logger.warning('Unhandled port status %s for port %u' % (
            reason, port_no))
        return []

    def advertise(self):
        """Called periodically to advertise services (eg. IPv6 RAs)."""
        ofmsgs = []
        now = time.time()
        if (self.dp.advertise_interval and
                now - self._last_advertise_sec > self.dp.advertise_interval):
            for vlan in list(self.dp.vlans.values()):
                for route_manager in list(self.route_manager_by_ipv.values()):
                    ofmsgs.extend(route_manager.advertise(vlan))
            self._last_advertise_sec = now
        return ofmsgs

    def datapath_connect(self, dp_id, discovered_up_port_nums):
        """Handle Ryu datapath connection event and provision pipeline.

        Args:
            dp_id (int): datapath ID.
            discovered_up_port_nums (list): datapath ports that are up as ints.
        Returns:
            list: OpenFlow messages to send to datapath.
        """
        if self._ignore_dpid(dp_id):
            return []
        self.logger.info('Cold start configuring DP')
        ofmsgs = []
        ofmsgs.extend(self._add_default_flows())
        ofmsgs.extend(self._add_ports_and_vlans(discovered_up_port_nums))
        ofmsgs.extend(self._add_controller_learn_flow())
        self.dp.running = True
        return ofmsgs

    def datapath_disconnect(self, dp_id):
        """Handle Ryu datapath disconnection event.

        Args:
            dp_id (int): datapath ID.
        """
        if not self._ignore_dpid(dp_id):
            self.dp.running = False
            self.logger.warning('datapath down')

    def _port_add_acl(self, port, cold_start=False):
        ofmsgs = []
        acl_table = self.dp.tables['port_acl']
        in_port_match = acl_table.match(in_port=port.number)
        if cold_start:
            ofmsgs.extend(acl_table.flowdel(in_port_match))
        acl_allow_inst = valve_of.goto_table(self.dp.tables['vlan'])
        if port.acl_in:
            ofmsgs.extend(valve_acl.build_acl_ofmsgs(
                [port.acl_in], acl_table, acl_allow_inst,
                self.dp.highest_priority, self.dp.meters,
                port_num=port.number))
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
        null_vlan.vid = ofp.OFPVID_NONE
        return self._port_add_vlan_rules(port, null_vlan, push_vlan_inst)

    def _port_add_vlan_tagged(self, port, vlan, forwarding_table, mirror_act):
        vlan_inst = [
            valve_of.goto_table(forwarding_table)
        ]
        if mirror_act:
            vlan_inst = [valve_of.apply_actions(mirror_act)] + vlan_inst
        return self._port_add_vlan_rules(port, vlan, vlan_inst)

    def _find_forwarding_table(self, vlan):
        if vlan.acl_in:
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

    def _port_delete_flows(self, port, hosts):
        ofmsgs = []
        ofmsgs.extend(self._delete_all_port_match_flows(port))
        ofmsgs.extend(self.dp.tables['eth_dst'].flowdel(out_port=port.number))
        if port.permanent_learn:
            eth_src_table = self.dp.tables['eth_src']
            for eth_src in hosts:
                ofmsgs.extend(eth_src_table.flowdel(
                    match=eth_src_table.match(eth_src=eth_src)))
        return ofmsgs

    def ports_add(self, dp_id, port_nums, cold_start=False):
        """Handle the addition of ports.

        Args:
            dp_id (int): datapath ID.
            port_num (list): list of port numbers.
            cold_start (bool): True if configuring datapath from scratch.
        Returns:
            list: OpenFlow messages, if any.
        """
        if self._ignore_dpid(dp_id):
            return []

        ofmsgs = []
        vlans_with_ports_added = set()
        eth_src_table = self.dp.tables['eth_src']
        vlan_table = self.dp.tables['vlan']

        for port_num in port_nums:
            if valve_of.ignore_port(port_num):
                continue
            if port_num not in self.dp.ports:
                self.logger.info(
                    'Ignoring port:%u not present in configuration file' % port_num)
                continue

            port = self.dp.ports[port_num]
            port.dyn_phys_up = True
            self.logger.info('Port %s up, configuring' % port)

            if not port.running():
                continue

            # Port is a mirror destination; drop all input packets
            if port.mirror_destination:
                ofmsgs.append(vlan_table.flowdrop(
                    match=vlan_table.match(in_port=port_num),
                    priority=self.dp.highest_priority))
                continue

            # Port has LACP processing enabled.
            if port.lacp:
                ofmsgs.append(eth_src_table.flowcontroller(
                    eth_src_table.match(
                        in_port=port.number,
                        eth_type=ether.ETH_TYPE_SLOW,
                        eth_dst=valve_packet.SLOW_PROTOCOL_MULTICAST),
                    priority=self.dp.highest_priority))

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
                mirror_act = []
                # Add mirroring if any
                if port.mirror:
                    mirror_act = [valve_of.output_port(port.mirror)]
                # Add port/to VLAN rules.
                ofmsgs.extend(self._port_add_vlans(port, mirror_act))

            for vlan in port_vlans:
                vlans_with_ports_added.add(vlan)

        # Only update flooding rules if not cold starting.
        if not cold_start:
            for vlan in vlans_with_ports_added:
                ofmsgs.extend(self.flood_manager.build_flood_rules(vlan))

        return ofmsgs

    def port_add(self, dp_id, port_num):
        """Handle addition of a single port.

        Args:
            dp_id (int): datapath ID.
            port_num (list): list of port numbers.
        Returns:
            list: OpenFlow messages, if any.
        """
        return self.ports_add(dp_id, [port_num])

    def ports_delete(self, dp_id, port_nums):
        """Handle the deletion of ports.

        Args:
            dp_id (int): datapath ID.
            port_nums (list): list of port numbers.
        Returns:
            list: OpenFlow messages, if any.
        """
        if self._ignore_dpid(dp_id):
            return []

        ofmsgs = []
        vlans_with_deleted_ports = set()

        for port_num in port_nums:
            if valve_of.ignore_port(port_num):
                continue
            if port_num not in self.dp.ports:
                continue
            port = self.dp.ports[port_num]
            port.dyn_phys_up = False
            self.logger.info('%s down' % port)

            # TODO: when mirroring an entire port, we install flows
            # in eth_dst output a copy to the mirror port. If the mirror
            # port goes down then those flows will be deleted stopping
            # forwarding for that host. They are garbage collected by
            # hard timeout anyway, but it would be good to "relearn them".
            if not port.mirror_destination:
                ofmsgs.extend(self._port_delete_flows(port, port.hosts()))
            for vlan in port.vlans():
                vlans_with_deleted_ports.add(vlan)

        for vlan in vlans_with_deleted_ports:
            ofmsgs.extend(self.flood_manager.build_flood_rules(
                vlan, modify=True))

        return ofmsgs

    def port_delete(self, dp_id, port_num):
        return self.ports_delete(dp_id, [port_num])

    def lacp_handler(self, pkt_meta):
        """Handle a LACP packet.

        We are a currently a passive, non-aggregateable LACP partner.

        Args:
            pkt_meta (PacketMeta): packet for control plane.
        Returns:
            list: OpenFlow messages, if any.
        """
        ofmsgs = []
        if (pkt_meta.eth_dst == valve_packet.SLOW_PROTOCOL_MULTICAST and
                pkt_meta.eth_type == ether.ETH_TYPE_SLOW and
                pkt_meta.port.lacp):
            pkt_meta.reparse_all()
            lacp_pkt = valve_packet.parse_lacp_pkt(pkt_meta.pkt)
            if not lacp_pkt:
                return ofmsgs
            pkt = valve_packet.lacp_reqreply(
                pkt_meta.vlan.faucet_mac,
                pkt_meta.vlan.faucet_mac, pkt_meta.port.number, pkt_meta.port.number,
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
            ofmsgs = [valve_of.packetout(pkt_meta.port.number, pkt.data)]
        return ofmsgs

    def control_plane_handler(self, pkt_meta):
        """Handle a packet probably destined to FAUCET's route managers.

        For example, next hop resolution or ICMP echo requests.

        Args:
            pkt_meta (PacketMeta): packet for control plane.
        Returns:
            list: OpenFlow messages, if any.
        """
        ofmsgs = []
        if (pkt_meta.eth_dst == pkt_meta.vlan.faucet_mac or
                not valve_packet.mac_addr_is_unicast(pkt_meta.eth_dst)):
            for route_manager in list(self.route_manager_by_ipv.values()):
                if pkt_meta.eth_type in route_manager.CONTROL_ETH_TYPES:
                    pkt_meta.reparse_ip(route_manager.ETH_TYPE)
                    ofmsgs = route_manager.control_plane_handler(pkt_meta)
                    break
        return ofmsgs

    def _known_up_dpid_and_port(self, dp_id, in_port):
        """Returns True if datapath and port are known and running.

        Args:
            dp_id (int): datapath ID.
            in_port (int): port number.
        Returns:
            bool: True if datapath and port are known and running.
        """
        if (not self._ignore_dpid(dp_id) and not valve_of.ignore_port(in_port) and
                self.dp.running and in_port in self.dp.ports):
            return True
        return False

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

    def _edge_dp_for_host(self, valves, dp_id, pkt_meta):
        """Simple distributed unicast learning.

        Args:
            valves (list): of all Valves (datapaths).
            dp_id (int): DPID of datapath packet received on.
            pkt_meta (PacketMeta): PacketMeta instance for packet received.
        Returns:
            Valve instance or None (of edge datapath where packet received)
        """
        # TODO: simplest possible unicast learning.
        # We find just one port that is the shortest unicast path to
        # the destination. We could use other factors (eg we could
        # load balance over multiple ports based on destination MAC).
        # TODO: each DP learns independently. An edge DP could
        # call other valves so they learn immediately without waiting
        # for packet in.
        # TODO: edge DPs could use a different forwarding algorithm
        # (for example, just default switch to a neighbor).
        # Find port that forwards closer to destination DP that
        # has already learned this host (if any).
        eth_src = pkt_meta.eth_src
        vlan_vid = pkt_meta.vlan.vid
        for other_dpid, other_valve in list(valves.items()):
            if other_dpid == dp_id:
                continue
            other_dp = other_valve.dp
            other_dp_host_cache = other_dp.vlans[vlan_vid].host_cache
            if eth_src in other_dp_host_cache:
                host = other_dp_host_cache[eth_src]
                if host.edge:
                    return other_dp
        return None

    def _learn_host(self, valves, dp_id, pkt_meta):
        """Possibly learn a host on a port.

        Args:
            dp_id (int): DPID of datapath packet received on.
            valves (list): of all Valves (datapaths).
            pkt_meta (PacketMeta): PacketMeta instance for packet received.
        Returns:
            list: OpenFlow messages, if any.
        """
        learn_port = pkt_meta.port
        ofmsgs = []

        if learn_port.stack is not None:
            edge_dp = self._edge_dp_for_host(valves, dp_id, pkt_meta)
            # No edge DP may have learned this host yet.
            if edge_dp is None:
                return ofmsgs

            learn_port = self.dp.shortest_path_port(edge_dp.name)
            self.logger.info(
                'host learned via stack port to %s' % edge_dp.name)

        ofmsgs.extend(self.host_manager.learn_host_on_vlan_port(
            learn_port, pkt_meta.vlan, pkt_meta.eth_src))

        return ofmsgs

    def parse_rcv_packet(self, in_port, vlan_vid, eth_type, data, pkt, eth_pkt):
        """Parse a received packet into a PacketMeta instance.

        Args:
            in_port (int): port packet was received on.
            vlan_vid (int): VLAN VID of port packet was received on.
            eth_type (int): Ethernet type of packet.
            data (bytes): Raw packet data.
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
            data, pkt, eth_pkt, port, vlan, eth_src, eth_dst, eth_type)

    def _port_learn_ban_rules(self, pkt_meta):
        """Limit learning to a maximum configured on this port.

        Args:
            pkt_meta: PacketMeta instance.
        Returns:
            list: OpenFlow messages, if any.
        """
        ofmsgs = []

        port = pkt_meta.port
        eth_src = pkt_meta.eth_src
        hosts = port.hosts()

        if len(hosts) == port.max_hosts:
            ofmsgs.append(self.host_manager.temp_ban_host_learning_on_port(
                port))
            port.dyn_learn_ban_count += 1
            self.logger.info(
                'max hosts %u reached on port %u, '
                'temporarily banning learning on this port, '
                'and not learning %s' % (
                    port.max_hosts, port.number, eth_src))
            return ofmsgs
        return ofmsgs

    def _vlan_learn_ban_rules(self, pkt_meta):
        """Limit learning to a maximum configured on this VLAN.

        Args:
            pkt_meta: PacketMeta instance.
        Returns:
            list: OpenFlow messages, if any.
        """
        ofmsgs = []
        vlan = pkt_meta.vlan
        eth_src = pkt_meta.eth_src
        hosts_count = vlan.hosts_count()
        if (vlan.max_hosts is not None and
                hosts_count == vlan.max_hosts and
                eth_src not in vlan.host_cache):
            ofmsgs.append(self.host_manager.temp_ban_host_learning_on_vlan(
                vlan))
            vlan.dyn_learn_ban_count += 1
            self.logger.info(
                'max hosts %u reached on vlan %u, '
                'temporarily banning learning on this vlan, '
                'and not learning %s' % (
                    vlan.max_hosts, vlan.vid, eth_src))
        return ofmsgs

    def update_config_metrics(self, metrics):
        """Update gauge/metrics for configuration.

        metrics (FaucetMetrics): container of Prometheus metrics.
        """
        metrics.faucet_config_dp_name.labels(
            dp_id=hex(self.dp.dp_id), name=self.dp.name).set(
                self.dp.dp_id)
        for table_id, table in list(self.dp.tables_by_id.items()):
            metrics.faucet_config_table_names.labels(
                dp_id=hex(self.dp.dp_id), name=table.name).set(table_id)

    def update_metrics(self, metrics):
        """Update Gauge/metrics.

        metrics (FaucetMetrics or None): container of Prometheus metrics.
        """
        # Clear the exported MAC learning.
        dp_id = hex(self.dp.dp_id)
        for _, label_dict, _ in metrics.learned_macs.collect()[0].samples:
            if label_dict['dp_id'] == dp_id:
                metrics.learned_macs.labels(
                    dp_id=label_dict['dp_id'], vlan=label_dict['vlan'],
                    port=label_dict['port'], n=label_dict['n']).set(0)

        for vlan in list(self.dp.vlans.values()):
            hosts_count = vlan.hosts_count()
            metrics.vlan_hosts_learned.labels(
                dp_id=dp_id, vlan=vlan.vid).set(hosts_count)
            metrics.vlan_learn_bans.labels(
                dp_id=dp_id, vlan=vlan.vid).set(vlan.dyn_learn_ban_count)
            for ipv in vlan.ipvs():
                neigh_cache_size = len(vlan.neigh_cache_by_ipv(ipv))
                metrics.vlan_neighbors.labels(
                    dp_id=dp_id, vlan=vlan.vid, ipv=ipv).set(neigh_cache_size)
            for port in vlan.get_ports():
                for i, host in enumerate(sorted(port.hosts(vlans=[vlan]))):
                    mac_int = int(host.replace(':', ''), 16)
                    metrics.learned_macs.labels(
                        dp_id=dp_id, vlan=vlan.vid,
                        port=port.number, n=i).set(mac_int)
                metrics.port_learn_bans.labels(
                    dp_id=dp_id, port=port.number).set(port.dyn_learn_ban_count)

    def rcv_packet(self, dp_id, valves, pkt_meta):
        """Handle a packet from the dataplane (eg to re/learn a host).

        The packet may be sent to us also in response to FAUCET
        initiating IPv6 neighbor discovery, or ARP, to resolve
        a nexthop.

        Args:
            dp_id (int): datapath ID.
            valves (dict): all datapaths, indexed by datapath ID.
            pkt_meta (PacketMeta): packet for control plane.
        Return:
            list: OpenFlow messages, if any.
        """
        if not self._known_up_dpid_and_port(dp_id, pkt_meta.port.number):
            return []
        if not pkt_meta.vlan.vid in self.dp.vlans:
            self.logger.warning('Packet_in for unexpected VLAN %s' % pkt_meta.vlan.vid)
            return []

        ofmsgs = []
        control_plane_handled = False
        learn_from_pkt = True

        if valve_packet.mac_addr_is_unicast(pkt_meta.eth_src):
            self.logger.debug(
                'Packet_in src:%s in_port:%d vid:%s' % (
                    pkt_meta.eth_src,
                    pkt_meta.port.number,
                    pkt_meta.vlan.vid))

            lacp_ofmsgs = self.lacp_handler(pkt_meta)
            if lacp_ofmsgs:
                learn_from_pkt = False
                ofmsgs.extend(lacp_ofmsgs)

            elif self.L3:
                control_plane_ofmsgs = self.control_plane_handler(pkt_meta)
                if control_plane_ofmsgs:
                    control_plane_handled = True
                    ofmsgs.extend(control_plane_ofmsgs)

        if self._rate_limit_packet_ins():
            return ofmsgs

        ban_port_rules = self._port_learn_ban_rules(pkt_meta)
        if ban_port_rules:
            ofmsgs.extend(ban_port_rules)
            return ofmsgs

        ban_vlan_rules = self._vlan_learn_ban_rules(pkt_meta)
        if ban_vlan_rules:
            ofmsgs.extend(ban_vlan_rules)
            return ofmsgs

        if learn_from_pkt:
            ofmsgs.extend(
                self._learn_host(valves, dp_id, pkt_meta))

            # Add FIB entries, if routing is active and not already handled
            # by control plane.
            if self.L3 and not control_plane_handled:
                for route_manager in list(self.route_manager_by_ipv.values()):
                    ofmsgs.extend(route_manager.add_host_fib_route_from_pkt(pkt_meta))

        return ofmsgs

    def host_expire(self):
        """Expire hosts not recently re/learned.

        Expire state from the host manager only; the switch does its own flow
        expiry.
        """
        if not self.dp.running:
            return
        now = time.time()
        for vlan in list(self.dp.vlans.values()):
            self.host_manager.expire_hosts_from_vlan(vlan, now)

    def _get_acl_config_changes(self, new_dp):
        """Detect any config changes to ACLs.

        Args:
            new_dp (DP): new dataplane configuration.
        Returns:
            changed_acls (dict): ACL ID map to new/changed ACLs.
        """
        changed_acls = {}
        for acl_id, new_acl in list(new_dp.acls.items()):
            if acl_id not in self.dp.acls:
                changed_acls[acl_id] = new_acl
                self.logger.info('ACL %s new' % acl_id)
            else:
                if new_acl != self.dp.acls[acl_id]:
                    changed_acls[acl_id] = new_acl
                    self.logger.info('ACL %s changed' % acl_id)
        return changed_acls

    def _get_vlan_config_changes(self, new_dp):
        """Detect any config changes to VLANs.

        Args:
            new_dp (DP): new dataplane configuration.
        Returns:
            changes (tuple) of:
                deleted_vlans (set): deleted VLAN IDs.
                changed_vlans (set): changed/added VLAN IDs.
        """
        deleted_vlans = set([])
        for vid in list(self.dp.vlans.keys()):
            if vid not in new_dp.vlans:
                deleted_vlans.add(vid)

        changed_vlans = set([])
        for vid, new_vlan in list(new_dp.vlans.items()):
            if vid not in self.dp.vlans:
                changed_vlans.add(vid)
                self.logger.info('VLAN %s added' % vid)
            else:
                old_vlan = self.dp.vlans[vid]
                if old_vlan != new_vlan:
                    if not old_vlan.ignore_subconf(new_vlan):
                        changed_vlans.add(vid)
                        self.logger.info('VLAN %s config changed' % vid)
                else:
                    # Preserve current VLAN including current
                    # dynamic state like caches, if VLAN and ports
                    # did not change at all.
                    new_dp.vlans[vid].merge_dyn(old_vlan)

        if not deleted_vlans and not changed_vlans:
            self.logger.info('no VLAN config changes')

        return (deleted_vlans, changed_vlans)

    def _get_port_config_changes(self, new_dp, changed_vlans, changed_acls):
        """Detect any config changes to ports.

        Args:
            new_dp (DP): new dataplane configuration.
            changed_vlans (set): changed/added VLAN IDs.
            changed_acls (dict): ACL ID map to new/changed ACLs.
        Returns:
            changes (tuple) of:
                all_ports_changed (bool): True if all ports changed.
                deleted_ports (set): deleted port numbers.
                changed_ports (set): changed/added port numbers.
                changed_acl_ports (set): changed ACL only port numbers.
        """
        all_ports_changed = False
        changed_ports = set([])
        changed_acl_ports = set([])

        for port_no, new_port in list(new_dp.ports.items()):
            if port_no not in self.dp.ports:
                # Detected a newly configured port
                changed_ports.add(port_no)
                self.logger.info('port %s added' % port_no)
            else:
                old_port = self.dp.ports[port_no]
                # An existing port has configs changed
                if new_port != old_port:
                    # TODO: we assume if port config had sub config
                    # changed, it must have been the ACL.
                    if old_port.ignore_subconf(new_port):
                        changed_acl_ports.add(port_no)
                        self.logger.info('port %s ACL changed' % port_no)
                    else:
                        changed_ports.add(port_no)
                        self.logger.info('port %s reconfigured' % port_no)
                elif new_port.acl_in in changed_acls:
                    # If the port has ACL changed.
                    changed_acl_ports.add(port_no)
                    self.logger.info('port %s ACL changed' % port_no)

        # TODO: optimize case where only VLAN ACL changed.
        for vid in changed_vlans:
            for port in new_dp.vlans[vid].get_ports():
                changed_ports.add(port.number)

        deleted_ports = set([])
        for port_no in list(self.dp.ports.keys()):
            if port_no not in new_dp.ports:
                deleted_ports.add(port_no)

        if changed_ports == set(new_dp.ports.keys()):
            self.logger.info('all ports config changed')
            all_ports_changed = True
        elif (not changed_ports and
              not deleted_ports and
              not changed_acl_ports):
            self.logger.info('no port config changes')

        return (all_ports_changed, deleted_ports,
                changed_ports, changed_acl_ports)

    def _get_config_changes(self, new_dp):
        """Detect any config changes.

        Args:
            new_dp (DP): new dataplane configuration.
        Returns:
            changes (tuple) of:
                deleted_ports (set): deleted port numbers.
                changed_ports (set): changed/added port numbers.
                changed_acl_ports (set): changed ACL only port numbers.
                deleted_vlans (set): deleted VLAN IDs.
                changed_vlans (set): changed/added VLAN IDs.
                all_ports_changed (bool): True if all ports changed.
        """
        changed_acls = self._get_acl_config_changes(new_dp)
        deleted_vlans, changed_vlans = self._get_vlan_config_changes(new_dp)
        (all_ports_changed, deleted_ports,
         changed_ports, changed_acl_ports) = self._get_port_config_changes(
             new_dp, changed_vlans, changed_acls)
        return (deleted_ports, changed_ports, changed_acl_ports,
                deleted_vlans, changed_vlans, all_ports_changed)

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
        cold_start = True
        ofmsgs = []

        if all_ports_changed:
            self.dp = new_dp
        else:
            cold_start = False
            if deleted_ports:
                self.logger.info('ports deleted: %s' % deleted_ports)
                ofmsgs.extend(self.ports_delete(self.dp.dp_id, deleted_ports))
            if deleted_vlans:
                self.logger.info('VLANs deleted: %s' % deleted_vlans)
                for vid in deleted_vlans:
                    vlan = self.dp.vlans[vid]
                    ofmsgs.extend(self._del_vlan(vlan))
            if changed_ports:
                ofmsgs.extend(self.ports_delete(self.dp.dp_id, changed_ports))
            self.dp = new_dp
            if changed_vlans:
                self.logger.info('VLANs changed/added: %s' % changed_vlans)
                for vid in changed_vlans:
                    vlan = self.dp.vlans[vid]
                    ofmsgs.extend(self._del_vlan(vlan))
                    ofmsgs.extend(self._add_vlan(vlan, set()))
            if changed_ports:
                self.logger.info('ports changed/added: %s' % changed_ports)
                ofmsgs.extend(self.ports_add(self.dp.dp_id, changed_ports))
            if changed_acl_ports:
                self.logger.info('ports with ACL only changed: %s' % changed_acl_ports)
                for port_num in changed_acl_ports:
                    port = self.dp.ports[port_num]
                    ofmsgs.extend(self._port_add_acl(port, cold_start=True))

        return cold_start, ofmsgs

    def reload_config(self, new_dp):
        """Reload configuration new_dp.

        Following config changes are currently supported:
            - Port config: support all available configs (e.g. native_vlan, acl_in)
                & change operations (add, delete, modify) a port
            - ACL config:support any modification, currently reload all rules
                belonging to an ACL
            - VLAN config: enable, disable routing, etc...

        Args:
            new_dp (DP): new dataplane configuration.
        Returns:
            tuple of:
                cold_start (bool): whether cold starting.
                ofmsgs (list): OpenFlow messages.
        """
        cold_start = False
        ofmsgs = []
        if self.dp.running:
            self.logger.info('reload configuration')
            cold_start, ofmsgs = self._apply_config_changes(
                new_dp, self._get_config_changes(new_dp))
            if cold_start:
                self.dp = new_dp
                ofmsgs = self.datapath_connect(
                    self.dp.dp_id, list(self.dp.ports.keys()))
        else:
            self.logger.info('skipping configuration because datapath not up')
        return (cold_start, ofmsgs)

    def _add_faucet_vips(self, route_manager, vlan, faucet_vips):
        ofmsgs = []
        for faucet_vip in faucet_vips:
            assert self.dp.stack is None, 'stacking + routing not yet supported'
            ofmsgs.extend(route_manager.add_faucet_vip(vlan, faucet_vip))
            self.L3 = True
        return ofmsgs

    def add_route(self, vlan, ip_gw, ip_dst):
        """Add route to VLAN routing table."""
        route_manager = self.route_manager_by_ipv[ip_dst.version]
        return route_manager.add_route(vlan, ip_gw, ip_dst)

    def del_route(self, vlan, ip_dst):
        """Delete route from VLAN routing table."""
        route_manager = self.route_manager_by_ipv[ip_dst.version]
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
            for route_manager in list(self.route_manager_by_ipv.values()):
                ofmsgs.extend(route_manager.resolve_gateways(vlan, now))
        return ofmsgs

    def get_config_dict(self):
        """Render configuration as a dict, suitable for returning via API call.

        Returns:
            dict: current configuration.
        """
        dps_dict = {
            self.dp.name: self.dp.to_conf()
            }
        vlans_dict = {}
        for vlan in list(self.dp.vlans.values()):
            vlans_dict[vlan.name] = vlan.to_conf()
        acls_dict = {}
        for acl_id, acl in list(self.dp.acls.items()):
            acls_dict[acl_id] = acl.to_conf()
        return {
            'dps': dps_dict,
            'vlans': vlans_dict,
            'acls': acls_dict,
            }

    def flow_timeout(self, table_id, match):
        ofmsgs = []
        if table_id in (self.dp.tables['eth_src'].table_id, self.dp.tables['eth_dst'].table_id):
            in_port = None
            eth_src = None
            eth_dst = None
            vid = None
            match_oxm_fields = match.to_jsondict()['OFPMatch']['oxm_fields']
            for field in match_oxm_fields:
                if isinstance(field, dict):
                    value = field['OXMTlv']
                    if value['field'] == 'eth_src':
                        eth_src = value['value']
                    if value['field'] == 'eth_dst':
                        eth_dst = value['value']
                    if value['field'] == 'vlan_vid':
                        vid = value['value'] & ~ofp.OFPVID_PRESENT
                    if value['field'] == 'in_port':
                        in_port = value['value']
            if eth_src and vid and in_port:
                vlan = self.dp.vlans[vid]
                ofmsgs.extend(
                    self.host_manager.src_rule_expire(vlan, in_port, eth_src))
            elif eth_dst and vid:
                vlan = self.dp.vlans[vid]
                ofmsgs.extend(self.host_manager.dst_rule_expire(vlan, eth_dst))
        return ofmsgs


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
                if not (isinstance(prop, parser.OFPTableFeaturePropOxm) and prop.type == 8):
                    continue
                tfm_matches = set(sorted([oxm.type for oxm in prop.oxm_ids]))
                if tfm_matches != table.restricted_match_types:
                    self.logger.info(
                        'table %s ID %s match TFM config %s != pipeline %s' % (
                            tfm_table.name, tfm_table.table_id,
                            tfm_matches, table.restricted_match_types))

    def switch_features(self, dp_id, msg):
        ryu_table_loader = tfm_pipeline.LoadRyuTables(
            self.dp.pipeline_config_dir, self.PIPELINE_CONF)
        self.logger.info('loading pipeline configuration')
        ofmsgs = self._delete_all_valve_flows()
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
