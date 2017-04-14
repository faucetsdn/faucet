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

IDLE_TIMEOUT_MARGIN = 10 #seconds

class HostCacheEntry(object):

    def __init__(self, eth_src, port, edge, permanent, now,
                 src_rule_expired=False):
        self.eth_src = eth_src
        self.port = port
        self.edge = edge
        self.permanent = permanent
        self.cache_time = now
        self.src_rule_expired = src_rule_expired


class ValveHostManager(object):

    def __init__(self, logger, eth_src_table, eth_dst_table,
                 learn_timeout, low_priority, host_priority,
                 valve_in_match, valve_flowmod, valve_flowdel, valve_flowdrop,
                 use_hard_timeout):
        self.logger = logger
        self.eth_src_table = eth_src_table
        self.eth_dst_table = eth_dst_table
        self.learn_timeout = learn_timeout
        self.low_priority = low_priority
        self.host_priority = host_priority
        self.valve_in_match = valve_in_match
        self.valve_flowmod = valve_flowmod
        self.valve_flowdel = valve_flowdel
        self.valve_flowdrop = valve_flowdrop
        self.use_hard_timeout = use_hard_timeout

    def temp_ban_host_learning_on_vlan(self, vlan):
        return self.valve_flowdrop(
            self.eth_src_table,
            self.valve_in_match(self.eth_src_table, vlan=vlan),
            priority=(self.low_priority + 1),
            hard_timeout=self.host_priority)

    def build_port_out_inst(self, vlan, port):
        dst_act = []
        if not vlan.port_is_tagged(port.number) and port.stack is None:
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
        ofmsgs = []
        expired_hosts = []
        for eth_src, host_cache_entry in vlan.host_cache.items():
            if not host_cache_entry.permanent:
                host_cache_entry_age = now - host_cache_entry.cache_time
                if host_cache_entry_age > self.learn_timeout:
                    expired_hosts.append(host_cache_entry)
        if expired_hosts:
            for host_cache_entry in expired_hosts:
                if (not self.use_hard_timeout and
                        not host_cache_entry.src_rule_expired):
                    self.logger.info(
                            'refreshing host %s from vlan %u',
                            host_cache_entry.eth_src, vlan.vid)
                    ofmsgs.extend(self.learn_host_on_vlan_port(
                        host_cache_entry.port,
                        vlan, host_cache_entry.eth_src,
                        clear_old_rule=False))
                else:
                    eth_src = host_cache_entry.eth_src
                    self._remove_expired_host_on_vlan(eth_src, vlan)

        return ofmsgs

    def expire_hosts_on_port(self, in_port, vlan):
        for eth_src, host_cache_entry in list(vlan.host_cache.iteritems()):
            if host_cache_entry.port.number == in_port:
                self._remove_expired_host_on_vlan(eth_src, vlan)

    def _remove_expired_host_on_vlan(self, eth_src, vlan):
        del vlan.host_cache[eth_src]
        self.logger.info(
            'expiring host %s from vlan %u', eth_src, vlan.vid)
        self.logger.info(
            '%u recently active hosts on vlan %u',
            len(vlan.host_cache), vlan.vid)

    def learn_host_on_vlan_port(self, port, vlan, eth_src, clear_old_rule=True):
        now = time.time()
        in_port = port.number
        ofmsgs = []

        # Don't relearn same host on same port if recently learned.
        # TODO: this is a good place to detect and react to a loop,
        # if we detect a host moving rapidly between ports.
        if eth_src in vlan.host_cache:
            host_cache_entry = vlan.host_cache[eth_src]
            if host_cache_entry.port.number == in_port:
                cache_age = now - host_cache_entry.cache_time
                if cache_age < 2:
                    return ofmsgs

        # hosts learned on this port never relearned
        if port.permanent_learn:
            src_rule_hard_timeout = 0
            src_rule_idle_timeout = 0
            dst_rule_idle_timeout = 0

            # antispoof this host
            ofmsgs.append(self.valve_flowdrop(
                self.eth_src_table,
                self.valve_in_match(
                    self.eth_src_table, vlan=vlan, eth_src=eth_src),
                priority=(self.host_priority - 2)))
        else:
            if clear_old_rule:
                ofmsgs.extend(self.delete_host_from_vlan(eth_src, vlan))
            if self.use_hard_timeout:
                #Add a jitter to avoid whole bunch of hosts timeout simultaneously
                src_rule_idle_timeout = 0
                dst_rule_idle_timeout = 0
                src_rule_hard_timeout = self.learn_timeout + random.randint(0,5)
            else:
                src_rule_hard_timeout = 0
                src_rule_idle_timeout = self.learn_timeout - IDLE_TIMEOUT_MARGIN
                dst_rule_idle_timeout = self.learn_timeout + IDLE_TIMEOUT_MARGIN
        # Idle_timeout is used for both src and dst table, with a longer timeout
        # in dst table. When a host is disconnected, controller expects to see
        # flowremoved event and it removes the host from cache.
        # If not, it re-installs both src and st rules thus refreshing the timeouts.
        # This is to make sure that dst rule always expires after src rule.
        ofmsgs.append(self.valve_flowmod(
            self.eth_src_table,
            self.valve_in_match(
                self.eth_src_table, in_port=in_port,
                vlan=vlan, eth_src=eth_src),
            priority=(self.host_priority - 1),
            inst=[valve_of.goto_table(self.eth_dst_table)],
            idle_timeout=src_rule_idle_timeout,
            hard_timeout=src_rule_hard_timeout))

        # update datapath to output packets to this mac via the associated port
        ofmsgs.append(self.valve_flowmod(
            self.eth_dst_table,
            self.valve_in_match(
                self.eth_dst_table, vlan=vlan, eth_dst=eth_src),
            priority=self.host_priority,
            inst=self.build_port_out_inst(vlan, port),
            idle_timeout=dst_rule_idle_timeout))

        host_cache_entry = HostCacheEntry(
            eth_src,
            port,
            port.stack is None,
            port.permanent_learn,
            now)
        vlan.host_cache[eth_src] = host_cache_entry

        self.logger.info(
            'learned %u hosts on vlan %u', len(vlan.host_cache), vlan.vid)

        return ofmsgs

    def host_mark_src_rule_expired(self, in_port, vlan, eth_src):
        host_cache_entry = vlan.host_cache[eth_src]
        if host_cache_entry.port.number == in_port:
            host_cache_entry.src_rule_expired = True
