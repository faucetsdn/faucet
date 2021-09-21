"""Abstraction of an OF table."""

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
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import functools
import hashlib
import struct
from faucet import valve_of
from faucet.faucet_pipeline import ValveTableConfig


class ValveTable:  # pylint: disable=too-many-arguments,too-many-instance-attributes
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
            f'{next_table.name} not configured as next table in {self.name}')
        return valve_of.goto_table(next_table)

    def goto_this(self):
        return valve_of.goto_table(self)

    def goto_miss(self, next_table):
        """Add miss goto table instruction."""
        assert next_table.name == self.table_config.miss_goto, (
            f'{next_table.name} not configured as miss table in {self.name}')
        return valve_of.goto_table(next_table)

    @staticmethod
    def set_field(**kwds):
        """Return set field action."""
        # raise exception if unknown set field.
        valve_of.match_from_dict(kwds)
        return valve_of.set_field(**kwds)

    def set_external_forwarding_requested(self):
        """Set field for external forwarding requested."""
        return self.set_field(**{valve_of.EXTERNAL_FORWARDING_FIELD: valve_of.PCP_EXT_PORT_FLAG})

    def set_no_external_forwarding_requested(self):
        """Set field for no external forwarding requested."""
        return self.set_field(**{valve_of.EXTERNAL_FORWARDING_FIELD: valve_of.PCP_NONEXT_PORT_FLAG})

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
    @functools.lru_cache(maxsize=1024)
    def match(in_port=None, vlan=None,  # pylint: disable=too-many-arguments
              eth_type=None, eth_src=None, eth_dst=None, eth_dst_mask=None,
              icmpv6_type=None, nw_proto=None, nw_dst=None, metadata=None,
              metadata_mask=None, vlan_pcp=None, udp_src=None, udp_dst=None):
        """Compose an OpenFlow match rule."""
        match_dict = valve_of.build_match_dict(
            in_port, vlan, eth_type, eth_src,
            eth_dst, eth_dst_mask, icmpv6_type,
            nw_proto, nw_dst, metadata, metadata_mask,
            vlan_pcp, udp_src, udp_dst)
        return valve_of.match(match_dict)

    def _verify_flowmod(self, flowmod):
        match_fields = flowmod.match.items()
        if valve_of.is_flowdel(flowmod):
            if self.table_id != valve_of.ofp.OFPTT_ALL:
                for match_type, match_field in match_fields:
                    assert match_type in self.match_types, (
                        f'{match_type} match in table {self.name}')
        else:
            # TODO: ACL builder should not use ALL table.
            if self.table_id == valve_of.ofp.OFPTT_ALL:
                return
            assert not (flowmod.priority == 0 and match_fields), (
                f'default flow cannot have matches on table {self.name}: {flowmod}')
            for match_type, match_field in match_fields:
                assert match_type in self.match_types, (
                    f'{match_type} match in table {self.name}')
                config_mask = self.match_types[match_type]
                flow_mask = isinstance(match_field, tuple)
                assert config_mask or (not config_mask and not flow_mask), (
                    f'{match_type} configured mask {config_mask} but flow mask '
                    f'{flow_mask} in table {self.name} ({flowmod})')
                if self.exact_match and match_fields:
                    assert len(self.match_types) == len(match_fields), (
                        f'exact match table {self.name} matches {self.match_types} '
                        f'do not match flow matches {match_fields} ({flowmod})')

    def _trim_actions(self, actions):
        new_actions = []
        pending_actions = []
        for action in actions:
            if action.type in (valve_of.ofp.OFPAT_GROUP, valve_of.ofp.OFPAT_OUTPUT):
                new_actions.extend(pending_actions)
                new_actions.append(action)
                pending_actions = []
            else:
                pending_actions.append(action)
        set_fields = {action.key for action in new_actions if valve_of.is_set_field(action)}
        if self.table_id != valve_of.ofp.OFPTT_ALL and set_fields:
            assert set_fields.issubset(self.set_fields), (
                f'unexpected set fields {set_fields} configured {self.set_fields} in {self.name}')
        return new_actions

    @functools.lru_cache()
    def _trim_inst(self, inst):
        """Discard empty/actions on packets that are not output and not goto another table."""
        inst_types = {instruction.type for instruction in inst}
        if valve_of.ofp.OFPIT_APPLY_ACTIONS in inst_types:
            goto_present = valve_of.ofp.OFPIT_GOTO_TABLE in inst_types
            new_inst = []
            for instruction in inst:
                if instruction.type == valve_of.ofp.OFPIT_APPLY_ACTIONS:
                    # If no goto present, this is the last set of actions that can take place
                    if not goto_present:
                        instruction.actions = self._trim_actions(instruction.actions)
                    # Always drop an apply actions instruction with no actions.
                    if not instruction.actions:
                        continue
                new_inst.append(instruction)
            return tuple(new_inst)
        return inst

    def flowmod(self, match=None, priority=None,  # pylint: disable=too-many-arguments
                inst=None, command=valve_of.ofp.OFPFC_ADD, out_port=0,
                out_group=0, hard_timeout=0, idle_timeout=0, cookie=None):
        """Helper function to construct a flow mod message with cookie."""
        if priority is None:
            priority = 0  # self.dp.lowest_priority
        if not match:
            match = self.match()
        if inst is None:
            inst = ()
        if cookie is None:
            cookie = self.flow_cookie
        flags = 0
        if self.notify_flow_removed:
            flags = valve_of.ofp.OFPFF_SEND_FLOW_REM
        if inst:
            inst = self._trim_inst(inst)
        flowmod = valve_of.flowmod(
            cookie,
            command,
            self.table_id,
            priority,
            out_port,
            out_group,
            match,
            tuple(inst),
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
            inst=())

    def flowcontroller(self, match=None, priority=None, inst=None, max_len=96):
        """Add flow outputting to controller."""
        if inst is None:
            inst = ()
        return self.flowmod(
            match=match,
            priority=priority,
            inst=(valve_of.apply_actions(
                (valve_of.output_controller(max_len),)),) + inst)


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
        ofmsgs.extend(valve_of.groupadd(
            group_id=self.group_id, buckets=self.buckets))
        self.table.entries[self.group_id] = self
        return ofmsgs

    def delete(self):
        """Return flow to delete an existing group entry."""
        if self.group_id in self.table.entries:
            del self.table.entries[self.group_id]
        return valve_of.groupdel(group_id=self.group_id)


class ValveGroupTable:
    """Wrap access to group table."""

    entries = None  # type: dict

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
