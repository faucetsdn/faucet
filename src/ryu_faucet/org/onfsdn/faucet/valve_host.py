# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2015 Brad Cowie, Christopher Lorier and Joe Stringer.
# Copyright (C) 2015 Research and Education Advanced Network New Zealand Ltd.
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


class HostCacheEntry(object):

    def __init__(self, eth_src, permanent, now):
        self.eth_src = eth_src
        self.permanent = permanent
        self.cache_time = now


class ValveHostManager(object):

    def __init__(self, eth_src_table, eth_dst_table,
                 valve_in_match, valve_flowmod, valve_flowdel):
        self.eth_src_table = eth_src_table
        self.eth_dst_table = eth_dst_table
        self.valve_in_match = valve_in_match
        self.valve_flowmod = valve_flowmod
        self.valve_flowdel = valve_flowdel

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
