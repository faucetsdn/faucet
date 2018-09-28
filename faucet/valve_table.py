"""Abstraction of an OF table."""

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
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import hashlib
import struct

from faucet import valve_of
from faucet.faucet_pipeline import ValveTableConfig


class ValveTable: # pylint: disable=too-many-arguments,too-many-instance-attributes
    """Wrapper for an OpenFlow table."""

    def __init__(self, name, table_config,
                 flow_cookie, notify_flow_removed=False, next_tables=None):
        self.name = name
        self.table_config = table_config
        self.table_id = self.table_config.table_id
        self.set_fields = self.table_config.set_fields
        self.exact_match = self.table_config.exact_match
        self.match_types = None
        self.metadata_match = self.table_config.metadata_match
        self.metadata_write = self.table_config.metadata_write
        if next_tables:
            self.next_tables = next_tables
        else:
            self.next_tables = []
        if self.table_config.match_types:
            self.match_types = {}
            for field, mask in self.table_config.match_types:
                self.match_types[field] = mask
        self.flow_cookie = flow_cookie
        self.notify_flow_removed = notify_flow_removed

    def goto(self, next_table):
        """Add goto next table instruction."""
        assert next_table.name in self.table_config.next_tables, (
            '%s not configured as next table in %s' % (
                next_table.name, self.name))
        return valve_of.goto_table(next_table)

    def goto_this(self):
        return valve_of.goto_table(self)

    def goto_miss(self, next_table):
        """Add miss goto table instruction."""
        assert next_table.name == self.table_config.miss_goto, (
            '%s not configured as miss table in %s' % (
                next_table.name, self.name))
        return valve_of.goto_table(next_table)

    def set_field(self, **kwds):
        """Return set field action."""
        for field in kwds.keys():
            assert (self.table_id == valve_of.ofp.OFPTT_ALL or
                    field in self.set_fields), (
                        '%s not configured as set field in %s' % (field, self.name))
        return valve_of.set_field(**kwds)

    def set_vlan_vid(self, vlan_vid):
        """Set VLAN VID with VID_PRESENT flag set.

        Args:
            vid (int): VLAN VID
        Returns:
            ryu.ofproto.ofproto_v1_3_parser.OFPActionSetField: set VID with VID_PRESENT.
        """
        return self.set_field(vlan_vid=valve_of.vid_present(vlan_vid))

    # TODO: verify actions
    @staticmethod
    def match(in_port=None, vlan=None, # pylint: disable=too-many-arguments
              eth_type=None, eth_src=None, eth_dst=None, eth_dst_mask=None,
              icmpv6_type=None, nw_proto=None, nw_dst=None, metadata=None,
              metadata_mask=None):
        """Compose an OpenFlow match rule."""
        match_dict = valve_of.build_match_dict(
            in_port, vlan, eth_type, eth_src,
            eth_dst, eth_dst_mask, icmpv6_type,
            nw_proto, nw_dst, metadata, metadata_mask)
        return valve_of.match(match_dict)

    def _verify_flowmod(self, flowmod):
        if valve_of.is_flowdel(flowmod):
            return
        if flowmod.priority == 0:
            assert not flowmod.match.items(), (
                'default flow cannot have matches')
        elif self.match_types:
            match_fields = flowmod.match.items()
            for match_type, match_field in match_fields:
                assert match_type in self.match_types, (
                    '%s match in table %s' % (match_type, self.name))
                config_mask = self.match_types[match_type]
                flow_mask = isinstance(match_field, tuple)
                assert config_mask or (not config_mask and not flow_mask), (
                    '%s configured mask %s but flow mask %s in table %s (%s)' % (
                        match_type, config_mask, flow_mask, self.name, flowmod))
            if self.exact_match:
                assert len(self.match_types) == len(match_fields), (
                    'exact match table matches %s do not match flow matches %s (%s)' % (
                        self.match_types, match_fields, flowmod))

    def flowmod(self, match=None, priority=None, # pylint: disable=too-many-arguments
                inst=None, command=valve_of.ofp.OFPFC_ADD, out_port=0,
                out_group=0, hard_timeout=0, idle_timeout=0, cookie=None):
        """Helper function to construct a flow mod message with cookie."""
        if priority is None:
            priority = 0 # self.dp.lowest_priority
        if not match:
            match = self.match()
        if inst is None:
            inst = []
        if cookie is None:
            cookie = self.flow_cookie
        flags = 0
        if self.notify_flow_removed:
            flags = valve_of.ofp.OFPFF_SEND_FLOW_REM
        flowmod = valve_of.flowmod(
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
        self._verify_flowmod(flowmod)
        return flowmod

    def flowdel(self, match=None, priority=None, out_port=valve_of.ofp.OFPP_ANY, strict=False):
        """Delete matching flows from a table."""
        command = valve_of.ofp.OFPFC_DELETE
        if strict:
            command = valve_of.ofp.OFPFC_DELETE_STRICT
        return self.flowmod(
            match=match, priority=priority, command=command,
            out_port=out_port, out_group=valve_of.ofp.OFPG_ANY)

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


class ValveGroupEntry:
    """Abstraction for a single OpenFlow group entry."""

    def __init__(self, table, group_id, buckets):
        self.table = table
        self.group_id = group_id
        self.update_buckets(buckets)

    def update_buckets(self, buckets):
        """Update entry with new buckets."""
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


class ValveGroupTable:
    """Wrap access to group table."""

    entries = None # type: dict


    def __init__(self):
        """Constructs a new object"""
        self.entries = {}

    @staticmethod
    def group_id_from_str(key_str):
        """Return a group ID based on a string key."""
        # TODO: does not handle collisions
        digest = hashlib.sha256(key_str.encode('utf-8')).digest()
        return struct.unpack('<L', digest[:4])[0]

    def get_entry(self, group_id, buckets):
        """Update entry with group_id with buckets, and return the entry."""
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


wildcard_table = ValveTable(
    'all', ValveTableConfig('all', valve_of.ofp.OFPTT_ALL), flow_cookie=0)
