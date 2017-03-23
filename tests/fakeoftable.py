# Copyright (C) 2015 Research and Innovation Advanced Network New Zealand Ltd.
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

import struct
from bitstring import Bits
from ryu.ofproto import ofproto_v1_3 as ofp
from ryu.ofproto import ofproto_v1_3_parser as parser
from ryu.lib import addrconv

class FakeOFTable():
    """Fake OFTable is a virtual openflow pipeline used for testing openflow controllers.

    The tables are populated using apply_ofmsgs and can be queried with
    is_ouput.
    """

    def __init__(self, num_tables):
        self.tables = []
        for i in range(0, num_tables):
            self.tables.append([])

    def apply_ofmsgs(self, ofmsgs):
        """This is used to update the fake flowtable.

        Adds, Deletes and modify flow modification messages are applied
        according to section 6.4 of the OpenFlow 1.3 specification."""
        for ofmsg in ofmsgs:
            if isinstance(ofmsg, parser.OFPFlowMod):
                table_id = ofmsg.table_id
                if table_id == ofp.OFPTT_ALL or table_id is None:
                    tables = self.tables
                else:
                    tables = [self.tables[table_id]]
                flowmod = FlowMod(ofmsg)
                for table in tables:
                    if ofmsg.command == ofp.OFPFC_ADD:
                        # From the 1.3 spec, section 6.4:
                        # For add requests (OFPFC_ADD) with the
                        # OFPFF_CHECK_OVERLAP flag set, the switch must first
                        # check for any overlapping flow entries in the
                        # requested table.  Two flow entries overlap if a
                        # single packet may match both, and both flow entries
                        # have the same priority, but the two flow entries
                        # don't have the exact same match.  If an overlap
                        # conflict exists between an existing flow entry and
                        # the add request, the switch must refuse the addition
                        # and respond with an ofp_error_msg with
                        # OFPET_FLOW_MOD_FAILED type and OFPFMFC_OVERLAP code.
                        #
                        # Without the check overlap flag it seems like it is
                        # possible that we can have overlapping flow table
                        # entries which will cause ambiguous behaviour. This is
                        # obviously unnacceptable so we will assume this is
                        # always set
                        add = True
                        for fte in table:
                            if flowmod.fte_matches(fte, strict=True):
                                table.remove(fte)
                                break
                            elif flowmod.overlaps(fte):
                                add = False
                                break
                        if add:
                            table.append(flowmod)
                    elif ofmsg.command == ofp.OFPFC_DELETE:
                        removals = []
                        for fte in table:
                            if flowmod.fte_matches(fte):
                                removals.append(fte)
                        for fte in removals:
                            table.remove(fte)
                    elif ofmsg.command == ofp.OFPFC_DELETE_STRICT:
                        for fte in table:
                            if flowmod.fte_matches(fte, strict=True):
                                table.remove(fte)
                                break
                    elif ofmsg.command == ofp.OFPFC_MODIFY:
                        for fte in table:
                            if flowmod.fte_matches(fte):
                                fte.instructions = flowmod.instructions
                    elif ofmsg.command == ofp.OFPFC_MODIFY_STRICT:
                        for fte in table:
                            if flowmod.fte_matches(fte, strict=True):
                                fte.instructions = flowmod.instructions
                                break
        self.sort_tables()

    def lookup(self, match):
        """Return the entries from flowmods that matches match.

        Searches each table in the pipeline for the entries that will be
        applied to the packet with fields represented by match.

        Arguments:
        match: a dictionary keyed by header field names with values.
                header fields not provided in match must be wildcarded for the
                entry to be considered matching.

        Returns: a list of the flowmods that will be applied to the packet
                represented by match
        """
        packet_dict = match.copy() # Packet headers may be modified
        instructions = []
        table_id = 0
        goto_table = True
        while goto_table:
            goto_table = False
            table = self.tables[table_id]
            matching_fte = None
            # find a matching flowmod
            for fte in table:
                if fte.pkt_matches(packet_dict):
                    matching_fte = fte
                    break
            # if a flowmod is found, make modifications to the match values and
            # determine if another lookup is necessary
            if matching_fte:
                for instruction in matching_fte.instructions:
                    instructions.append(instruction)
                    if instruction.type == ofp.OFPIT_GOTO_TABLE:
                        if table_id < instruction.table_id:
                            table_id = instruction.table_id
                            goto_table = True
                    elif instruction.type == ofp.OFPIT_APPLY_ACTIONS:
                        for action in instruction.actions:
                            if action.type == ofp.OFPAT_SET_FIELD:
                                packet_dict[action.key] = action.value
        return instructions

    def is_output(self, match, port=None, vid=None):
        """Return true if packets with match fields is output to port with
        correct vlan.

        If port is none it will return true if output to any port (including
        special ports) regardless of vlan tag.

        If vid is none it will return true if output to specified port
        regardless of vlan tag.

        To specify the packet should be output without a vlan tag set the
        OFPVID_PRESENT bit in vid is 0.

        Arguments:
        Match: a dictionary keyed by header field names with values.
        """
        # vid_stack represents the packet's vlan stack, innermost label listed
        # first
        match_vid = match.get('vlan_vid', 0)
        if match_vid & ofp.OFPVID_PRESENT != 0:
            vid_stack = [match_vid]
        else:
            vid_stack = []

        instructions = self.lookup(match)

        for instruction in instructions:
            if instruction.type == ofp.OFPIT_APPLY_ACTIONS:
                for action in instruction.actions:

                    if action.type == ofp.OFPAT_PUSH_VLAN:
                        vid_stack.append(ofp.OFPVID_PRESENT)

                    elif action.type == ofp.OFPAT_POP_VLAN:
                        vid_stack.pop()

                    elif action.type == ofp.OFPAT_SET_FIELD:
                        if action.key == 'vlan_vid':
                            vid_stack[-1] = action.value
                        else:
                            continue

                    elif action.type == ofp.OFPAT_OUTPUT:
                        if port is None:
                            return True

                        elif action.port == port:

                            if vid is None:
                                return True

                            elif vid & ofp.OFPVID_PRESENT == 0:
                                return len(vid_stack) == 0

                            else:
                                return\
                                    len(vid_stack) > 0 and vid == vid_stack[-1]

        return False

    def __str__(self):
        string = ""
        for table_id, table in enumerate(self.tables):
            string += "----- Table {0} -----\n".format(table_id)
            for flowmod in table:
                string += str(flowmod)
                string += "\n"
        return string

    def sort_tables(self):
        for table_id, table in enumerate(self.tables):
            self.tables[table_id] = sorted(table, reverse=True)
        return self.tables

    def parse_of_match(self, match):
        values_dict = {}
        masks_dict = {}

        return (values_dict, masks_dict)

class FlowMod(object):
    """Represents a flow modification message and its corresponding entry in
    the flow table.
    """


    MAC_MATCH_FIELDS = (
        'eth_src', 'eth_dst', 'arp_sha', 'arp_tha', 'ipv6_nd_sll',
        'ipv6_nd_tll'
        )
    IPV4_MATCH_FIELDS = ('ipv4_src', 'ipv4_dst', 'arp_spa', 'arp_tpa')
    IPV6_MATCH_FIELDS = ('ipv6_src', 'ipv6_dst', 'ipv6_nd_target')

    def __init__(self, flowmod):
        """flowmod is a ryu flow modification message object"""
        self.priority = flowmod.priority
        self.instructions = flowmod.instructions
        self.match_values = {}
        self.match_masks = {}
        self.out_port = None
        if (flowmod.command == ofp.OFPFC_DELETE or\
           flowmod.command == ofp.OFPFC_DELETE_STRICT) and\
           flowmod.out_port != ofp.OFPP_ANY:
            self.out_port = flowmod.out_port

        for key, v in flowmod.match.items():
            if isinstance(v, tuple):
                val, mask = v
            else:
                val = v
                mask = -1

            mask = self.match_to_bits(key, mask)
            val = self.match_to_bits(key, val) & mask
            self.match_values[key] = val
            self.match_masks[key] = mask

    def out_port_matches(self, other):
        """returns True if other has an output action to this flowmods
        output_port"""
        if self.out_port is None or self.out_port == ofp.OFPP_ANY:
            return True
        for instruction in other.instructions:
            if instruction.type == ofp.OFPIT_APPLY_ACTIONS:
                for action in instruction.actions:
                    if action.type == ofp.OFPAT_OUTPUT:
                        if action.port == self.out_port:
                            return True
        return False

    def pkt_matches(self, pkt_dict):
        """returns True if pkt_dict matches this flow table entry.

        args:
            pkt_dict - a dictionary keyed by flow table match fields with
                values
        if an element is included in the flow table entry match fields but not
        in the pkt_dict that is assumed to indicate a failed match
        """

        #TODO: add cookie and out_group
        for key, val in self.match_values.items():
            if key not in pkt_dict:
                return False
            else:
                val_bits = self.match_to_bits(key, pkt_dict[key])
                if val_bits != (val & self.match_masks[key]):
                    return False
        return True

    def fte_matches(self, other, strict=False):
        """returns True if the flow table entry other matches this flowmod.

        used for finding existing flow table entries that match with this
        flowmod.

        args:
            other - a flowmod object
            strict (bool) - whether to use strict matching (as defined in
                of1.3 specification section 6.4)
        """
        if not self.out_port_matches(other):
            return False
        if strict:
            return self.priority == other.priority and\
                   self.match_values == other.match_values and\
                   self.match_masks == other.match_masks
        else:
            for key, val in self.match_values.items():
                if key not in other.match_values:
                    return False
                else:
                    if other.match_values[key] & self.match_masks[key] != val:
                        return False
        return True


    def overlaps(self, other):
        """ returns True if any packet can match both self and other."""
        # This is different from the matches method as matches assumes an
        # undefined field is a failed match. In this case an undefined field is
        # potentially an overlap and therefore is considered success
        if other.priority != self.priority:
            return False
        for k, v in self.match_values.items():
            if k in other.match_values:
                if v & other.match_masks[k] != other.match_values[k]:
                    return False
                if other.match_values[k] & self.match_masks[k] != v:
                    return False
        return True

    def match_to_bits(self, key, val):
        """convert match fields and masks to bits objects.

        this allows for masked matching. Converting all match fields to the
        same object simplifies things (eg __str__).
        """
        if isinstance(val, Bits):
            return val

        if key in self.MAC_MATCH_FIELDS:
            if val is -1:
                val = Bits(int=-1, length=48)
            elif isinstance(val, str):
                val = Bits(bytes=addrconv.mac.text_to_bin(val), length=48)

        elif key in self.IPV4_MATCH_FIELDS:
            if val is -1:
                val = Bits(int=-1, length=32)
            elif isinstance(val, str):
                val = Bits(bytes=addrconv.ipv4.text_to_bin(val), length=32)

        elif key in self.IPV6_MATCH_FIELDS:
            if val is -1:
                val = Bits(int=-1, length=128)
            elif isinstance(val, str):
                val = Bits(bytes=addrconv.ipv6.text_to_bin(val), length=128)

        else:
            val = Bits(int=int(val), length=64)

        return val

    def __lt__(self, other):
        return self.priority < other.priority

    def __eq__(self, other):
        return self.priority == other.priority and\
               self.match_values == other.match_values and\
               self.match_masks == other.match_masks and\
               self.out_port == other.out_port and\
               self.instructions == other.instructions

    def __str__(self):
        string = 'priority: {0}'.format(self.priority)
        for key, val in self.match_values.items():
            mask = self.match_masks[key]
            string += ' {0}: {1}'.format(key, val)
            if mask.int != -1:
                string += '/{0}'.format(mask)
        string += ' Instructions: {0}'.format(str(self.instructions))
        return string
