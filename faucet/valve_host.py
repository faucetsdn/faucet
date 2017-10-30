"""Manage host learning on VLANs."""

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

import time
import random

from faucet import valve_of


class ValveHostManager(object):

    def __init__(self, logger, ports, vlans, eth_src_table, eth_dst_table,
                 learn_timeout, learn_jitter, learn_ban_timeout, low_priority, host_priority):
        self.logger = logger
        self.ports = ports
        self.vlans = vlans
        self.eth_src_table = eth_src_table
        self.eth_dst_table = eth_dst_table
        self.learn_timeout = learn_timeout
        self.learn_jitter = learn_jitter
        self.learn_ban_timeout = learn_ban_timeout
        self.low_priority = low_priority
        self.host_priority = host_priority

    def ban_rules(self, pkt_meta):
        """Limit learning to a maximum configured on this port/VLAN.

        Args:
            pkt_meta: PacketMeta instance.
        Returns:
            list: OpenFlow messages, if any.
        """
        ofmsgs = []

        port = pkt_meta.port
        eth_src = pkt_meta.eth_src
        vlan = pkt_meta.vlan

        if eth_src not in vlan.host_cache:
            if port.max_hosts:
                hosts = port.hosts()
                if len(hosts) == port.max_hosts:
                    ofmsgs.append(self._temp_ban_host_learning_on_port(port))
                    port.dyn_learn_ban_count += 1
                    self.logger.info(
                        'max hosts %u reached on %s, '
                        'temporarily banning learning on this port, '
                        'and not learning %s' % (
                            port.max_hosts, port, eth_src))
            if vlan.max_hosts:
                hosts_count = vlan.hosts_count()
                if hosts_count == vlan.max_hosts:
                    ofmsgs.append(self._temp_ban_host_learning_on_vlan(vlan))
                    vlan.dyn_learn_ban_count += 1
                    self.logger.info(
                        'max hosts %u reached on VLAN %u, '
                        'temporarily banning learning on this vlan, '
                        'and not learning %s on %s' % (
                            vlan.max_hosts, vlan.vid, eth_src, port))
        return ofmsgs

    def _temp_ban_host_learning_on_port(self, port):
        return self.eth_src_table.flowdrop(
            self.eth_src_table.match(in_port=port.number),
            priority=(self.low_priority + 1),
            hard_timeout=self.learn_ban_timeout)

    def _temp_ban_host_learning_on_vlan(self, vlan):
        return self.eth_src_table.flowdrop(
            self.eth_src_table.match(vlan=vlan),
            priority=(self.low_priority + 1),
            hard_timeout=self.learn_ban_timeout)

    def build_port_out_inst(self, vlan, port, port_number=None):
        """Return instructions to output a packet on a given port."""
        if port_number is None:
            port_number = port.number
        dst_act = []
        if not vlan.port_is_tagged(port) and port.stack is None:
            dst_act.append(valve_of.pop_vlan())
        dst_act.append(valve_of.output_port(port_number))

        if port.mirror is not None:
            mirror_acts = [valve_of.output_port(port.mirror)]
            dst_act.extend(mirror_acts)

        return [valve_of.apply_actions(dst_act)]

    def delete_host_from_vlan(self, eth_src, vlan):
        """Delete a host from a VLAN."""
        ofmsgs = []
        ofmsgs.extend(self.eth_src_table.flowdel(
            self.eth_src_table.match(vlan=vlan, eth_src=eth_src)))
        ofmsgs.extend(self.eth_dst_table.flowdel(
            self.eth_dst_table.match(vlan=vlan, eth_dst=eth_src)))
        return ofmsgs

    def expire_hosts_from_vlan(self, vlan, now):
        """Expire hosts from VLAN cache."""
        expired_hosts = vlan.expire_cache_hosts(now, self.learn_timeout)
        if expired_hosts:
            self.logger.info(
                '%u recently active hosts on VLAN %u, expired %s' % (
                    vlan.hosts_count(), vlan.vid, expired_hosts))

    def learn_host_timeouts(self, port):
        """Calculate flow timeouts for learning on a port."""
        # hosts learned on this port never relearned
        if port.permanent_learn:
            learn_timeout = 0
        else:
            learn_timeout = self.learn_timeout
            if self.learn_timeout:
                # Add a jitter to avoid whole bunch of hosts timeout simultaneously
                learn_timeout = int(max(abs(
                    self.learn_timeout -
                    (self.learn_jitter / 2) + random.randint(0, self.learn_jitter)), 2))

        # Update datapath to no longer send packets from this mac to controller
        # note the use of hard_timeout here and idle_timeout for the dst table
        # this is to ensure that the source rules will always be deleted before
        # any rules on the dst table. Otherwise if the dst table rule expires
        # but the src table rule is still being hit intermittantly the switch
        # will flood packets to that dst and not realise it needs to relearn
        # the rule
        # NB: Must be lower than highest priority otherwise it can match
        # flows destined to controller
        src_rule_idle_timeout = 0
        src_rule_hard_timeout = learn_timeout
        dst_rule_idle_timeout = learn_timeout
        return (src_rule_idle_timeout, src_rule_hard_timeout, dst_rule_idle_timeout)

    def learn_host_on_vlan_port_flows(self, port, vlan, eth_src, delete_existing,
                                      src_rule_idle_timeout, src_rule_hard_timeout,
                                      dst_rule_idle_timeout):
        """Return flows that implement learning a host on a port."""
        ofmsgs = []

        if port.permanent_learn:
            # Antispoofing rule for this MAC.
            ofmsgs.append(self.eth_src_table.flowdrop(
                self.eth_src_table.match(vlan=vlan, eth_src=eth_src),
                priority=(self.host_priority - 2)))
        else:
            # Delete any existing entries for MAC.
            # TODO: for LAGs, don't delete entries in the same LAG.
            if delete_existing:
                ofmsgs.extend(self.delete_host_from_vlan(eth_src, vlan))

        # Associate this MAC with source port.
        ofmsgs.append(self.eth_src_table.flowmod(
            self.eth_src_table.match(
                in_port=port.number, vlan=vlan, eth_src=eth_src),
            priority=(self.host_priority - 1),
            inst=[valve_of.goto_table(self.eth_dst_table)],
            hard_timeout=src_rule_hard_timeout,
            idle_timeout=src_rule_idle_timeout))

        # Output packets for this MAC to specified port.
        ofmsgs.append(self.eth_dst_table.flowmod(
            self.eth_dst_table.match(vlan=vlan, eth_dst=eth_src),
            priority=self.host_priority,
            inst=self.build_port_out_inst(vlan, port),
            idle_timeout=dst_rule_idle_timeout))

        # If port is in hairpin mode, install a special rule
        # that outputs packets destined to this MAC back out the same
        # port they came in (e.g. multiple hosts on same WiFi AP,
        # and FAUCET is switching between them on the same port).
        if port.hairpin:
            ofmsgs.append(self.eth_dst_table.flowmod(
                self.eth_dst_table.match(in_port=port.number, vlan=vlan, eth_dst=eth_src),
                priority=(self.host_priority + 1),
                inst=self.build_port_out_inst(vlan, port, port_number=valve_of.OFP_IN_PORT),
                idle_timeout=dst_rule_idle_timeout))

        return ofmsgs

    def learn_host_on_vlan_ports(self, port, vlan, eth_src, delete_existing=True):
        """Learn a host on a port."""
        now = time.time()
        ofmsgs = []

        ban_age = None
        learn_ban = False

        if port.loop_protect:
            if port.dyn_last_ban_time:
                ban_age = now - port.dyn_last_ban_time
            if ban_age and ban_age < 2:
                learn_ban = True

        if not learn_ban:
            entry = vlan.cached_host(eth_src)
            if entry is not None:
                cache_age = now - entry.cache_time
                if cache_age < 2:
                    # Don't relearn same host on same port if recently learned.
                    if entry.port == port:
                        return ofmsgs
                    elif port.loop_protect:
                        # Ban learning on a port if a host rapidly moves to another port.
                        if ban_age is None or ban_age > 2:
                            learn_ban = True
                            port.dyn_learn_ban_count += 1
                            ofmsgs.append(self._temp_ban_host_learning_on_port(port))
                            self.logger.info('rapid move of %s from %s to %s, temp loop ban %s' % (
                                eth_src, entry.port, port, port))
                        elif ban_age < 2:
                            learn_ban = True

        if learn_ban:
            port.dyn_last_ban_time = now
            return ofmsgs

        (src_rule_idle_timeout,
         src_rule_hard_timeout,
         dst_rule_idle_timeout) = self.learn_host_timeouts(port)

        ofmsgs.extend(self.learn_host_on_vlan_port_flows(
            port, vlan, eth_src, delete_existing,
            src_rule_idle_timeout, src_rule_hard_timeout,
            dst_rule_idle_timeout))

        vlan.add_cache_host(eth_src, port, now)

        self.logger.info(
            'learned %s on %s on VLAN %u (%u hosts total)' % (
                eth_src, port, vlan.vid, vlan.hosts_count()))

        return ofmsgs

    def flow_timeout(self, _table_id, _match):
        return []


class ValveHostFlowRemovedManager(ValveHostManager):
    """Trigger relearning on flow removed notifications.

    NOTE: not currently reliable.
    """

    def flow_timeout(self, table_id, match):
        ofmsgs = []
        if table_id in (self.eth_src_table.table_id, self.eth_dst_table.table_id):
            in_port = None
            eth_src = None
            eth_dst = None
            vid = None
            for field, value in list(match.items()):
                if field == 'in_port':
                    in_port = value
                elif field == 'eth_src':
                    eth_src = value
                elif field == 'eth_dst':
                    eth_dst = value
                elif field == 'vlan_vid':
                    vid = valve_of.devid_present(value)
            if vid:
                vlan = self.vlans[vid]
                if eth_src and in_port:
                    port = self.ports[in_port]
                    ofmsgs.extend(self._src_rule_expire(vlan, port, eth_src))
                elif eth_dst:
                    ofmsgs.extend(self._dst_rule_expire(vlan, eth_dst))
        return ofmsgs

    def expire_hosts_from_vlan(self, _vlan, _now):
        return

    def learn_host_timeouts(self, port):
        """Calculate flow timeouts for learning on a port."""
        # hosts learned on this port never relearned
        if port.permanent_learn:
            learn_timeout = 0
        else:
            # Add a jitter to avoid whole bunch of hosts timeout simultaneously
            learn_timeout = int(max(abs(
                self.learn_timeout -
                (self.learn_jitter / 2) + random.randint(0, self.learn_jitter)), 2))

        # Disable hard_time, dst rule expires after src rule.
        src_rule_idle_timeout = learn_timeout
        src_rule_hard_timeout = 0
        dst_rule_idle_timeout = learn_timeout + 2
        return (src_rule_idle_timeout, src_rule_hard_timeout, dst_rule_idle_timeout)

    def _src_rule_expire(self, vlan, port, eth_src):
        """When a src rule expires, the host is probably inactive or active in
        receiving but not sending. We mark just mark the host as expired."""
        ofmsgs = []
        entry = vlan.cached_host_on_port(eth_src, port)
        if entry is not None:
            entry.expired = True
            self.logger.info('expired src_rule for host %s' % eth_src)
        return ofmsgs

    def _dst_rule_expire(self, vlan, eth_dst):
        """Expiring a dst rule may indicate that the host is actively sending
        traffic but not receving. If the src rule not yet expires, we reinstall
        host rules."""
        ofmsgs = []
        if eth_dst in vlan.host_cache:
            entry = vlan.host_cache[eth_dst]
            if not entry.expired:
                ofmsgs.extend(self.learn_host_on_vlan_ports(
                    entry.port, vlan, eth_dst, False))
                self.logger.info(
                    'refreshing host %s from vlan %u' % (eth_dst, vlan.vid))
        return ofmsgs
