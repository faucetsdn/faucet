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
# distributed under the License is distributed on an "AS IS" BASISo
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import time
import random

import valve_of


class HostCacheEntry(object):

    def __init__(self, eth_src, port_num, edge, permanent, now):
        self.eth_src = eth_src
        self.port_num = port_num
        self.edge = edge
        self.permanent = permanent
        self.cache_time = now


class ValveHostManager(object):

    def __init__(self, logger, eth_src_table, eth_dst_table,
                 learn_timeout, learn_jitter, learn_ban_timeout, low_priority, host_priority,
                 valve_in_match, valve_flowmod, valve_flowdel, valve_flowdrop):
        self.logger = logger
        self.eth_src_table = eth_src_table
        self.eth_dst_table = eth_dst_table
        self.learn_timeout = learn_timeout
        self.learn_jitter = learn_jitter
        self.learn_ban_timeout = learn_ban_timeout
        self.low_priority = low_priority
        self.host_priority = host_priority
        self.valve_in_match = valve_in_match
        self.valve_flowmod = valve_flowmod
        self.valve_flowdel = valve_flowdel
        self.valve_flowdrop = valve_flowdrop

    def temp_ban_host_learning_on_port(self, port):
        return self.valve_flowdrop(
            self.eth_src_table,
            self.valve_in_match(self.eth_src_table, in_port=port.number),
            priority=(self.low_priority + 1),
            hard_timeout=self.learn_ban_timeout)

    def temp_ban_host_learning_on_vlan(self, vlan):
        return self.valve_flowdrop(
            self.eth_src_table,
            self.valve_in_match(self.eth_src_table, vlan=vlan),
            priority=(self.low_priority + 1),
            hard_timeout=self.learn_ban_timeout)

    def build_port_out_inst(self, vlan, port):
        dst_act = []
        if not vlan.port_is_tagged(port) and port.stack is None:
            dst_act.append(valve_of.pop_vlan())
        dst_act.append(valve_of.output_port(port.number))

        if port.mirror is not None:
            mirror_acts = [valve_of.output_port(port.mirror)]
            dst_act.extend(mirror_acts)

        return [valve_of.apply_actions(dst_act)]

    def delete_host_from_vlan(self, eth_src, vlan):
        ofmsgs = []
        # delete any existing ofmsgs for this vlan/mac combination on the
        # src mac table
        ofmsgs.extend(self.valve_flowdel(
            self.eth_src_table,
            self.valve_in_match(
                self.eth_src_table, vlan=vlan, eth_src=eth_src)))

        # delete any existing ofmsgs for this vlan/mac combination on the dst
        # mac table
        ofmsgs.extend(self.valve_flowdel(
            self.eth_dst_table,
            self.valve_in_match(
                self.eth_dst_table, vlan=vlan, eth_dst=eth_src)))

        return ofmsgs

    def expire_hosts_from_vlan(self, vlan, now):
        expired_hosts = []
        for eth_src, host_cache_entry in list(vlan.host_cache.items()):
            if not host_cache_entry.permanent:
                host_cache_entry_age = now - host_cache_entry.cache_time
                if host_cache_entry_age > self.learn_timeout:
                    expired_hosts.append(eth_src)
        if expired_hosts:
            for eth_src in expired_hosts:
                del vlan.host_cache[eth_src]
                self.logger.info(
                    'expiring host %s from vlan %u', eth_src, vlan.vid)
            self.logger.info(
                '%u recently active hosts on vlan %u',
                self.hosts_learned_on_vlan_count(vlan), vlan.vid)

    def hosts_learned_on_vlan_count(self, vlan):
        return len(vlan.host_cache)

    def learn_host_on_vlan_port(self, port, vlan, eth_src):
        now = time.time()
        in_port = port.number
        ofmsgs = []

        # Don't relearn same host on same port if recently learned.
        # TODO: this is a good place to detect and react to a loop,
        # if we detect a host moving rapidly between ports.
        if eth_src in vlan.host_cache:
            host_cache_entry = vlan.host_cache[eth_src]
            if host_cache_entry.port_num == in_port:
                cache_age = now - host_cache_entry.cache_time
                if cache_age < 2:
                    return ofmsgs

        # hosts learned on this port never relearned
        if port.permanent_learn:
            learn_timeout = 0

            # antispoof this host
            ofmsgs.append(self.valve_flowdrop(
                self.eth_src_table,
                self.valve_in_match(
                    self.eth_src_table, vlan=vlan, eth_src=eth_src),
                priority=(self.host_priority - 2)))
        else:
            # Add a jitter to avoid whole bunch of hosts timeout simultaneously
            learn_timeout = int(max(abs(
                self.learn_timeout -
                (self.learn_jitter / 2) + random.randint(0, self.learn_jitter)), 2))
            ofmsgs.extend(self.delete_host_from_vlan(eth_src, vlan))

        # Update datapath to no longer send packets from this mac to controller
        # note the use of hard_timeout here and idle_timeout for the dst table
        # this is to ensure that the source rules will always be deleted before
        # any rules on the dst table. Otherwise if the dst table rule expires
        # but the src table rule is still being hit intermittantly the switch
        # will flood packets to that dst and not realise it needs to relearn
        # the rule
        # NB: Must be lower than highest priority otherwise it can match
        # flows destined to controller
        ofmsgs.append(self.valve_flowmod(
            self.eth_src_table,
            self.valve_in_match(
                self.eth_src_table, in_port=in_port,
                vlan=vlan, eth_src=eth_src),
            priority=(self.host_priority - 1),
            inst=[valve_of.goto_table(self.eth_dst_table)],
            hard_timeout=learn_timeout))

        # update datapath to output packets to this mac via the associated port
        ofmsgs.append(self.valve_flowmod(
            self.eth_dst_table,
            self.valve_in_match(
                self.eth_dst_table, vlan=vlan, eth_dst=eth_src),
            priority=self.host_priority,
            inst=self.build_port_out_inst(vlan, port),
            idle_timeout=learn_timeout))

        host_cache_entry = HostCacheEntry(
            eth_src,
            in_port,
            port.stack is None,
            port.permanent_learn,
            now)
        vlan.host_cache[eth_src] = host_cache_entry

        self.logger.info(
            'learned %u hosts on vlan %u',
            self.hosts_learned_on_vlan_count(vlan),
            vlan.vid)

        return ofmsgs
