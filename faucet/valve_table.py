"""Abstraction of an OF table."""

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
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import hashlib
import struct

from faucet import valve_of


class ValveTable(object):
    """Wrapper for an OpenFlow table."""

    def __init__(self, table_id, name, restricted_match_types,
                 flow_cookie, notify_flow_removed=False):
        self.table_id = table_id
        self.name = name
        self.restricted_match_types = None
        if restricted_match_types:
            self.restricted_match_types = set(restricted_match_types)
        self.flow_cookie = flow_cookie
        self.notify_flow_removed = notify_flow_removed

    def match(self, in_port=None, vlan=None,
              eth_type=None, eth_src=None,
              eth_dst=None, eth_dst_mask=None,
              icmpv6_type=None,
              nw_proto=None, nw_dst=None):
        """Compose an OpenFlow match rule."""
        match_dict = valve_of.build_match_dict(
            in_port, vlan, eth_type, eth_src,
            eth_dst, eth_dst_mask, icmpv6_type,
            nw_proto, nw_dst)
        match = valve_of.match(match_dict)
        if self.restricted_match_types is not None:
            for match_type in match_dict:
                assert match_type in self.restricted_match_types, '%s match in table %s' % (
                    match_type, self.name)
        return match

    def flowmod(self, match=None, priority=None,
                inst=None, command=valve_of.ofp.OFPFC_ADD, out_port=0,
                out_group=0, hard_timeout=0, idle_timeout=0, cookie=None):
        """Helper function to construct a flow mod message with cookie."""
        if match is None:
            match = self.match()
        if priority is None:
            priority = 0 # self.dp.lowest_priority
        if inst is None:
            inst = []
        if cookie is None:
            cookie = self.flow_cookie
        flags = 0
        if self.notify_flow_removed:
            flags = valve_of.ofp.OFPFF_SEND_FLOW_REM
        return valve_of.flowmod(
            cookie,
            command,
            self.table_id,
            priority,
            out_port,
            out_group,
            match,
            inst,
            hard_timeout,
            idle_timeout,
            flags)

    def flowdel(self, match=None, priority=None, out_port=valve_of.ofp.OFPP_ANY, strict=False):
        """Delete matching flows from a table."""
        command = valve_of.ofp.OFPFC_DELETE
        if strict:
            command = valve_of.ofp.OFPFC_DELETE_STRICT
        return [
            self.flowmod(
                match=match,
                priority=priority,
                command=command,
                out_port=out_port,
                out_group=valve_of.ofp.OFPG_ANY)]

    def flowdrop(self, match=None, priority=None, hard_timeout=0):
        """Add drop matching flow to a table."""
        return self.flowmod(
            match=match,
            priority=priority,
            hard_timeout=hard_timeout,
            inst=[])

    def flowcontroller(self, match=None, priority=None, inst=None, max_len=96):
        """Add flow outputting to controller."""
        if inst is None:
            inst = []
        return self.flowmod(
            match=match,
            priority=priority,
            inst=[valve_of.apply_actions(
                [valve_of.output_controller(max_len)])] + inst)


class ValveGroupEntry(object):
    """Abstraction for a single OpenFlow group entry."""

    def __init__(self, table, group_id, buckets):
        self.table = table
        self.group_id = group_id
        self.update_buckets(buckets)

    def update_buckets(self, buckets):
        self.buckets = tuple(buckets)

    def add(self):
        """Return flows to add this entry to the group table."""
        ofmsgs = []
        ofmsgs.append(self.delete())
        ofmsgs.append(valve_of.groupadd(
            group_id=self.group_id, buckets=self.buckets))
        self.table.entries[self.group_id] = self
        return ofmsgs

    def modify(self):
        """Return flow to modify an existing group entry."""
        assert self.group_id in self.table.entries
        self.table.entries[self.group_id] = self
        return valve_of.groupmod(group_id=self.group_id, buckets=self.buckets)

    def delete(self):
        """Return flow to delete an existing group entry."""
        if self.group_id in self.table.entries:
            del self.table.entries[self.group_id]
        return valve_of.groupdel(group_id=self.group_id)


class ValveGroupTable(object):
    """Wrap access to group table."""

    entries = {} # type: dict

    @staticmethod
    def group_id_from_str(key_str):
        """Return a group ID based on a string key."""
        # TODO: does not handle collisions
        digest = hashlib.sha256(key_str.encode('utf-8')).digest()
        return struct.unpack('<L', digest[:4])[0]

    def get_entry(self, group_id, buckets):
        if group_id in self.entries:
            self.entries[group_id].update_buckets(buckets)
        else:
            self.entries[group_id] = ValveGroupEntry(
                self, group_id, buckets)
        return self.entries[group_id]

    def delete_all(self):
        """Delete all groups."""
        self.entries = {}
        return valve_of.groupdel()
