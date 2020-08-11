# Copyright (C) 2015 Research and Innovation Advanced Network New Zealand Ltd.
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

import sys
import argparse
import json
import ast
import heapq
import pprint

from collections import OrderedDict

from bitstring import Bits

from ryu.ofproto import ofproto_v1_3 as ofp
from ryu.ofproto import ofproto_v1_3_parser as parser
from ryu.ofproto import ofproto_parser as ofp_parser
from ryu.lib import addrconv


CONTROLLER_PORT = 4294967293
IN_PORT = 4294967288


class FakeOFTableException(Exception):
    """Indicates an erroneous flow or group mod"""


class DFS:
    """Provides a way of tracking the search through the FakeOFNetwork"""

    visited = None
    heap = None

    def __init__(self):
        self.visited = {}
        self.heap = []

    def visit(self, dp_id, pkt):
        """
        Notifies the DFS that a packet has visited the dp_id
        Args:
            dp_id: The DP ID for the node that is being visited
            pkt: The packet that is visiting the node
        """
        self.visited.setdefault(dp_id, [])
        if pkt not in self.visited[dp_id]:
            self.visited[dp_id].append(pkt)

    def has_visited(self, dp_id, pkt):
        """
        Returns true if the packet has visited the node DP ID before
        Args:
            dp_id: The DP ID for the node is being visited
            pkt: The packet that is visiting the node
        """
        if dp_id in self.visited:
            if pkt in self.visited[dp_id]:
                return True
        return False

    def peek(self):
        """
        Returns the first item in the heap (with the highest priority (smallest value))
        with popping from the heap
        Returns:
            dp_id, pkt
        """
        if not self.heap:
            return None, None
        item = self.heap[0]
        return item[1][0], item[1][1]

    def push(self, dp_id, pkt, priority):
        """
        Pushes the dp_id and pkt onto the heap with priority
        Args:
            dp_id:
            pkt:
            priority:
        """
        heapq.heappush(self.heap, (priority, (dp_id, tuple(pkt.items()))))

    def pop(self):
        """
        Obtains the item with the highest priority
        Returns:
            dp_id, pkt
        """
        if not self.heap:
            return None, None
        item = heapq.heappop(self.heap)
        return item[1][0], item[1][1]


class FakeOFNetwork:
    """
    FakeOFNetwork is a virtual openflow pipeline used for testing openflow controllers
    The network contains multiple FakeOFTables to represent multiple switches in a network
    """

    def __init__(self, valves_manager, num_tables, requires_tfm=True):
        """
        Args:
            valves_manager (ValvesManager): Valves manager class to resolve stack traversals
            num_tables (int): The number of tables to configure in each FakeOFTable
            requires_tfm (bool): Whether TFMs are required
        """
        self.valves_manager = valves_manager
        self.tables = {}
        for dp_id in self.valves_manager.valves:
            self.tables[dp_id] = FakeOFTable(dp_id, num_tables, requires_tfm)

    def apply_ofmsgs(self, dp_id, ofmsgs, ignore_errors=False):
        """Applies ofmsgs to a FakeOFTable for DP ID"""
        self.tables[dp_id].apply_ofmsgs(ofmsgs, ignore_errors=ignore_errors)

    def print_table(self, dp_id):
        """Prints the table in string format to STDERR"""
        sys.stderr.write('TABLE %x' % dp_id)
        sys.stderr.write(str(self.tables[dp_id]) + '\n')
        sys.stderr.write('======================\n\n')

    def shortest_path_len(self, src_dpid, dst_dpid):
        """Returns the length of the shortest path from the source to the destination"""
        src_valve = self.valves_manager.valves[src_dpid]
        dst_valve = self.valves_manager.valves[dst_dpid]
        if src_valve == dst_valve:
            return 1
        elif src_valve.dp.stack and dst_valve.dp.stack:
            return len(src_valve.dp.stack.shortest_path(dst_valve.dp.name))
        else:
            return 2

    def is_output(self, match, src_dpid, dst_dpid, port=None, vid=None, trace=False):
        """
        Traverses a packet through the network until we have searched everything
        or successfully output a packet to the destination with expected port and vid
        If port is None return True if output to any port (including special ports)
        regardless of VLAN tag.
        If vid is None return True if output to specified port regardless of VLAN tag.
        If vid OFPVID_PRESENT bit is 0, return True if output packet does not have
        a VLAN tag OR packet OFPVID_PRESENT is 0
        Args:
            match (dict): A dictionary keyed by header field names with values
            src_dpid: The source DP ID of the match packet entering the Fake OF network
            dst_dpid: The expected destination DP ID of the packet match
            port: The expected output port on the destination DP
            vid: The expected output vid on the destination DP
            trace (bool): Print the trace of traversing the tables
        Returns:
            true if packets with match fields is output to port with correct VLAN
        """
        found = False
        dfs = DFS()
        priority = self.shortest_path_len(src_dpid, dst_dpid)
        pkt = match.copy()
        dfs.push(src_dpid, pkt, priority)
        dfs.visit(src_dpid, pkt)
        while not found:
            # Search through the packet paths until we have searched everything or
            #   successfully output the packet to the destination in the expected format
            dp_id, pkt = dfs.pop()
            if dp_id is None or pkt is None:
                break
            pkt = dict(pkt)
            if dp_id == dst_dpid:
                # A packet has reached the destination, so test for the output
                found = self.tables[dp_id].is_output(pkt, port, vid, trace=trace)
                if not found and trace:
                    # A packet on the destination DP is not output in the expected state so
                    #   continue searching (flood reflection)
                    sys.stderr.write('Output is away from destination\n')
            if not found:
                # Packet not reached destination, so continue traversing
                if trace:
                    sys.stderr.write('FakeOFTable %s: %s\n' % (dp_id, pkt))
                port_outputs = self.tables[dp_id].get_port_outputs(pkt, trace=trace)
                valve = self.valves_manager.valves[dp_id]
                for out_port, out_pkts in port_outputs.items():
                    if out_port == IN_PORT:
                        # Rebind output to the packet in_port value
                        out_port = pkt['in_port']
                    if out_port not in valve.dp.ports:
                        # Ignore output to improper ports & controller
                        # TODO: Here we should actually send the packet to the
                        #   controller, and maybe install necessary rules to
                        #   help testing routing implementations
                        continue
                    for out_pkt in out_pkts:
                        port_obj = valve.dp.ports[out_port]
                        if port_obj.stack:
                            # Need to continue traversing through the FakeOFNetwork
                            adj_port = port_obj.stack['port']
                            adj_dpid = port_obj.stack['dp'].dp_id
                            new_pkt = out_pkt.copy()
                            new_pkt['in_port'] = adj_port.number
                            if not dfs.has_visited(adj_dpid, new_pkt):
                                # Add packet to the heap if we have not visited the node with
                                #   this packet before
                                priority = self.shortest_path_len(adj_dpid, dst_dpid)
                                dfs.push(adj_dpid, new_pkt, priority)
                                dfs.visit(adj_dpid, new_pkt)
                        elif trace:
                            # Output to non-stack port, can ignore this output
                            sys.stderr.write(
                                'Ignoring non-stack output %s:%s\n' % (valve.dp.name, out_port))
            if trace:
                sys.stderr.write('\n')
        return found

    def table_state(self, dp_id):
        """Return tuple of table hash & table str"""
        return self.tables[dp_id].table_state()

    def hash_table(self, dp_id):
        """Return a hash of a single FakeOFTable"""
        return self.tables[dp_id].__hash__()


class FakeOFTable:
    """Fake OFTable is a virtual openflow pipeline used for testing openflow
    controllers.

    The tables are populated using apply_ofmsgs and can be queried with
    is_output.
    """

    def __init__(self, dp_id, num_tables=1, requires_tfm=True):
        self.dp_id = dp_id
        self.tables = [[] for _ in range(0, num_tables)]
        self.groups = {}
        self.requires_tfm = requires_tfm
        self.tfm = {}

    def table_state(self):
        """Return tuple of table hash & table str"""
        table_str = str(self.tables)
        return (hash(frozenset(table_str)), table_str)

    def __hash__(self):
        """Return a host of the tables"""
        return hash(frozenset(str(self.tables)))

    def _apply_groupmod(self, ofmsg):
        """Maintain group table."""

        def _del(_ofmsg, group_id):
            if group_id == ofp.OFPG_ALL:
                self.groups = {}
                return
            if group_id in self.groups:
                del self.groups[group_id]

        def _add(ofmsg, group_id):
            if group_id in self.groups:
                raise FakeOFTableException(
                    'group already in group table: %s' % ofmsg)
            self.groups[group_id] = ofmsg

        def _modify(ofmsg, group_id):
            if group_id not in self.groups:
                raise FakeOFTableException(
                    'group not in group table: %s' % ofmsg)
            self.groups[group_id] = ofmsg

        _groupmod_handlers = {
            ofp.OFPGC_DELETE: _del,
            ofp.OFPGC_ADD: _add,
            ofp.OFPGC_MODIFY: _modify,
        }

        _groupmod_handlers[ofmsg.command](ofmsg, ofmsg.group_id)

    def _apply_flowmod(self, ofmsg):
        """Adds, Deletes and modify flow modification messages are applied
           according to section 6.4 of the OpenFlow 1.3 specification."""

        def _validate_flowmod_tfm(table_id, tfm_body, ofmsg):
            if not self.requires_tfm:
                return

            if table_id == ofp.OFPTT_ALL:
                if ofmsg.match.items() and not self.tfm:
                    raise FakeOFTableException(
                        'got %s with matches before TFM that defines tables'
                        % ofmsg)
                return

            if tfm_body is None:
                raise FakeOFTableException(
                    'got %s before TFM that defines table %u' % (
                        ofmsg, table_id
                        )
                    )

        def _add(table, flowmod):
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
            for fte in table:
                if flowmod.fte_matches(fte, strict=True):
                    table.remove(fte)
                    break
                if flowmod.overlaps(fte):
                    raise FakeOFTableException(
                        'Overlapping flowmods {} and {}'.format(
                            flowmod, fte))
            table.append(flowmod)

        def _del(table, flowmod):
            removals = [fte for fte in table if flowmod.fte_matches(fte)]
            for fte in removals:
                table.remove(fte)

        def _del_strict(table, flowmod):
            for fte in table:
                if flowmod.fte_matches(fte, strict=True):
                    table.remove(fte)
                    break

        def _modify(table, flowmod):
            for fte in table:
                if flowmod.fte_matches(fte):
                    fte.instructions = flowmod.instructions

        def _modify_strict(table, flowmod):
            for fte in table:
                if flowmod.fte_matches(fte, strict=True):
                    fte.instructions = flowmod.instructions
                    break

        _flowmod_handlers = {
            ofp.OFPFC_ADD: _add,
            ofp.OFPFC_DELETE: _del,
            ofp.OFPFC_DELETE_STRICT: _del_strict,
            ofp.OFPFC_MODIFY: _modify,
            ofp.OFPFC_MODIFY_STRICT: _modify_strict,
        }

        table_id = ofmsg.table_id
        tfm_body = self.tfm.get(table_id, None)

        if table_id == ofp.OFPTT_ALL or table_id is None:
            tables = self.tables
        else:
            tables = [self.tables[table_id]]

        _validate_flowmod_tfm(table_id, tfm_body, ofmsg)
        flowmod = FlowMod(ofmsg)

        for table in tables:
            _flowmod_handlers[ofmsg.command](table, flowmod)

        if tfm_body:
            for table in tables:
                entries = len(table)
                if entries > tfm_body.max_entries:
                    tfm_table_details = '%s : table %u %s full (%u/%u)' % (
                        self.dp_id, table_id, tfm_body.name, entries, tfm_body.max_entries)
                    flow_dump = '\n\n'.join(
                        (tfm_table_details, str(ofmsg), str(tfm_body)))
                    raise FakeOFTableException(flow_dump)

    def _apply_tfm(self, ofmsg):
        self.tfm = {body.table_id: body for body in ofmsg.body}

    def _apply_flowstats(self, ofmsg):
        """Update state of flow tables to match an OFPFlowStatsReply message.

        This assumes a tfm is not required."""
        self.tables = []
        self.requires_tfm = False
        self.tfm = {}
        for stat in ofmsg.body:
            while len(self.tables) <= stat.table_id:
                self.tables.append([])
            self.tables[stat.table_id].append(FlowMod(stat))

    def apply_ofmsgs(self, ofmsgs, ignore_errors=False):
        """Update state of test flow tables."""
        for ofmsg in ofmsgs:
            try:
                if isinstance(ofmsg, parser.OFPBarrierRequest):
                    continue
                if isinstance(ofmsg, parser.OFPPacketOut):
                    continue
                if isinstance(ofmsg, parser.OFPSetConfig):
                    continue
                if isinstance(ofmsg, parser.OFPSetAsync):
                    continue
                if isinstance(ofmsg, parser.OFPDescStatsRequest):
                    continue
                if isinstance(ofmsg, parser.OFPMeterMod):
                    # TODO: handle OFPMeterMod
                    continue
                if isinstance(ofmsg, parser.OFPTableFeaturesStatsRequest):
                    self._apply_tfm(ofmsg)
                    continue
                if isinstance(ofmsg, parser.OFPGroupMod):
                    self._apply_groupmod(ofmsg)
                    continue
                if isinstance(ofmsg, parser.OFPFlowMod):
                    self._apply_flowmod(ofmsg)
                    self.sort_tables()
                    continue
                if isinstance(ofmsg, parser.OFPFlowStatsReply):
                    self._apply_flowstats(ofmsg)
                    self.sort_tables()
                    continue
            except FakeOFTableException:
                if not ignore_errors:
                    raise
            if not ignore_errors:
                raise FakeOFTableException('Unsupported flow %s' % str(ofmsg))

    def single_table_lookup(self, match, table_id, trace=False):
        """
        Searches through a single table with `table_id` for entries
        that will be applied to the packet with fields represented by match
        Args:
            match (dict): A dictionary keyed by header field names with values
            table_id (int): The table ID to send the match packet through
            trace (bool): Print the trace of traversing the table
        Returns:
            matching_fte: First matching flowmod in the table
        """
        packet_dict = match.copy()
        table = self.tables[table_id]
        matching_fte = None
        # Find matching flowmods
        for fte in table:
            if fte.pkt_matches(packet_dict):
                matching_fte = fte
                break
        if trace:
            sys.stderr.write('%s: %s\n' % (table_id, matching_fte))
        return matching_fte

    def _process_instruction(self, match, instruction):
        """
        Process an instructions actions into an output dictionary
        Args:
            match (dict): A dictionary keyed by header field names with values
            instruction: The instruction being applied to the packet match
        Returns:
            outputs: OrderedDict of an output port to list of output packets
            packet_dict: final dictionary of the packet
        """
        outputs = OrderedDict()
        packet_dict = match.copy()
        pending_actions = []
        for action in instruction.actions:
            if action.type == ofp.OFPAT_OUTPUT:
                # Save the packet that is output to a port
                outputs.setdefault(action.port, [])
                outputs[action.port].append(packet_dict.copy())
                pending_actions = []
                continue

            pending_actions.append(action)

            if action.type == ofp.OFPAT_SET_FIELD:
                # Set field, modify a packet header
                packet_dict[action.key] = action.value
            elif action.type == ofp.OFPAT_PUSH_VLAN:
                if 'vlan_vid' in packet_dict and packet_dict['vlan_vid'] & ofp.OFPVID_PRESENT:
                    # Pushing on another tag, so create another
                    #   field for the encapsulated VID
                    packet_dict['encap_vid'] = packet_dict['vlan_vid']
                # Push the VLAN header to the packet
                packet_dict['vlan_vid'] = ofp.OFPVID_PRESENT
            elif action.type == ofp.OFPAT_POP_VLAN:
                # Remove VLAN header from the packet
                packet_dict.pop('vlan_vid')
                if 'encap_vid' in packet_dict:
                    # Move the encapsulated VID to the front
                    packet_dict['vlan_vid'] = packet_dict['encap_vid']
                    packet_dict.pop('encap_vid')
                else:
                    packet_dict['vlan_vid'] = 0
            elif action.type == ofp.OFPAT_GROUP:
                # Group mod so make sure that we process the group buckets
                if action.group_id not in self.groups:
                    raise FakeOFTableException('output group not in group table: %s' % action)
                buckets = self.groups[action.group_id].buckets
                for bucket in buckets:
                    bucket_outputs, _, _ = self._process_instruction(packet_dict, bucket)
                    for out_port, out_pkts in bucket_outputs.items():
                        outputs.setdefault(out_port, [])
                        outputs[out_port].extend(out_pkts)
                        pending_actions = []

        return outputs, packet_dict, pending_actions

    def get_table_output(self, match, table_id, trace=False):
        """
        Send a packet through a single table and return the output
        ports mapped to the output packet
        Args:
            match (dict): A dictionary keyed by header field names with values
            table_id (int): The table ID to send the packet match through
            trace (bool): Print the trace of traversing the table
        Returns:
            outputs: OrderedDict of an output port to output packet map
            packet_dict: The last version of the packet
            next_table: Table ID of the next table
        """
        next_table = None
        packet_dict = match.copy()
        outputs = OrderedDict()
        matching_fte = self.single_table_lookup(match, table_id, trace)
        pending_actions = []
        if matching_fte:
            for instruction in matching_fte.instructions:
                if instruction.type == ofp.OFPIT_GOTO_TABLE:
                    if table_id < instruction.table_id:
                        next_table = instruction.table_id
                    else:
                        raise FakeOFTableException('goto to lower table ID')
                elif instruction.type == ofp.OFPIT_APPLY_ACTIONS:
                    if not instruction.actions:
                        raise FakeOFTableException('no-op instruction actions')
                    instruction_outputs, packet_dict, pending_actions = self._process_instruction(
                        packet_dict, instruction)
                    for out_port, out_pkts in instruction_outputs.items():
                        outputs.setdefault(out_port, [])
                        outputs[out_port].extend(out_pkts)
                elif instruction.type == ofp.OFPIT_WRITE_METADATA:
                    metadata = packet_dict.get('metadata', 0)
                    mask = instruction.metadata_mask
                    mask_compl = mask ^ 0xFFFFFFFFFFFFFFFF
                    packet_dict['metadata'] = (metadata & mask_compl) | (instruction.metadata & mask)
        if next_table:
            pending_actions = []
        if pending_actions:
            raise FakeOFTableException('flow performs actions on packet after output with no goto: %s' % matching_fte)
        return outputs, packet_dict, next_table

    def get_output(self, match, trace=False):
        """
        Get all of the outputs of the tables with the output packets
        for each table in the FakeOFTable that match progresses through
        Args:
            match (dict): A dictionary keyed by header field names with values
            trace (bool): Print the trace of traversing the table
        Returns:
            table_outputs: map from table_id output to output ports & packets
                for that table
        """
        table_outputs = {}
        table_id = 0
        next_table = True
        packet_dict = match.copy()
        while next_table:
            next_table = False
            outputs, packet_dict, next_table_id = self.get_table_output(
                packet_dict, table_id, trace)
            table_outputs[table_id] = outputs
            next_table = next_table_id is not None
            table_id = next_table_id
        return table_outputs

    def get_port_outputs(self, match, trace=False):
        """
        Get all of the outputs of the tables with the output packets
        for each table in the FakeOFTable that match progresses through
        Args:
            match (dict): A dictionary keyed by header field names with value
            trace (bool): Print the trace of traversing the table
        Returns:
            table_outputs: Map from output port number to a list of unique output packets
        """
        port_outputs = {}
        table_id = 0
        next_table = True
        packet_dict = match.copy()
        while next_table:
            next_table = False
            outputs, packet_dict, next_table_id = self.get_table_output(
                packet_dict, table_id, trace)
            for out_port, out_pkts in outputs.items():
                port_outputs.setdefault(out_port, [])
                # Remove duplicate entries from the list
                for out_pkt in out_pkts:
                    if out_pkt not in port_outputs[out_port]:
                        port_outputs[out_port].append(out_pkt)
            next_table = next_table_id is not None
            table_id = next_table_id
        return port_outputs

    def is_full_output(self, match, port=None, vid=None, trace=False):
        """
        If port is None return True if output to any port (including special ports)
        regardless of VLAN tag.
        If vid is None return True if output to specified port regardless of VLAN tag.
        If vid OFPVID_PRESENT bit is 0, return True if output packet does not have
        a VLAN tag OR packet OFPVID_PRESENT is 0
        Args:
            match (dict): A dictionary keyed by header field names with values
            port: The expected output port
            vid: The expected output vid
            trace (bool): Print the trace of traversing the tables
        Returns:
            true if packets with match fields is output to port with correct VLAN
        """
        table_outputs = self.get_output(match, trace)
        if trace:
            sys.stderr.write(pprint.pformat(table_outputs) + '\n')
        in_port = match.get('in_port')
        for table_outputs in table_outputs.values():
            for out_port, out_pkts in table_outputs.items():
                for out_pkt in out_pkts:
                    if port == out_port and port == out_pkt['in_port']:
                        continue
                    if port is None:
                        # Port is None & outputting so return true
                        return True
                    if vid is None:
                        # Vid is None, return true if output to specified port
                        if port == out_port:
                            return True
                        if out_port == ofp.OFPP_IN_PORT and port == in_port:
                            # In some cases we want to match to specifically ofp.OFPP_IN_PORT
                            #   otherwise we treat ofp.OFPP_IN_PORT as the match in_port
                            return True
                    if port == out_port or (out_port == ofp.OFPP_IN_PORT and port == in_port):
                        # Matching port, so check matching VID
                        if vid & ofp.OFPVID_PRESENT == 0:
                            # If OFPVID_PRESENT bit is 0 then packet should not have a VLAN tag
                            return ('vlan_vid' not in out_pkt or
                                    out_pkt['vlan_vid'] & ofp.OFPVID_PRESENT == 0)
                        # VID specified, check if matching expected
                        return 'vlan_vid' in out_pkt and vid == out_pkt['vlan_vid']
        return False

    def lookup(self, match, trace=False):
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
        packet_dict = match.copy()  # Packet headers may be modified
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
            if trace:
                sys.stderr.write('%d: %s\n' % (table_id, matching_fte))
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
                    elif instruction.type == ofp.OFPIT_WRITE_METADATA:
                        metadata = packet_dict.get('metadata', 0)
                        mask = instruction.metadata_mask
                        mask_compl = mask ^ 0xFFFFFFFFFFFFFFFF
                        packet_dict['metadata'] = (metadata & mask_compl)\
                            | (instruction.metadata & mask)
        return (instructions, packet_dict)

    def flow_count(self):
        """Return number of flow tables rules"""
        return sum(map(len, self.tables))

    def is_output(self, match, port=None, vid=None, trace=False):
        """Return true if packets with match fields is output to port with
        correct vlan.

        If port is none it will return true if output to any port (including
        special ports) regardless of vlan tag.

        If vid is none it will return true if output to specified port
        regardless of vlan tag.

        To specify checking that the packet should not have a vlan tag, set the
        OFPVID_PRESENT bit in vid to 0.

        Arguments:
        Match: a dictionary keyed by header field names with values.
        """

        full_output = self.is_full_output(match.copy(), port, vid, trace)

        def _output_result(action, vid_stack, port, vid):
            if port is None:
                return True
            in_port = match.get('in_port')
            result = None
            if action.port == port:
                if port == in_port:
                    result = None
                elif vid is None:
                    result = True
                elif vid & ofp.OFPVID_PRESENT == 0:
                    result = not vid_stack
                else:
                    result = bool(vid_stack and vid == vid_stack[-1])
            elif action.port == ofp.OFPP_IN_PORT and port == in_port:
                result = True
            return result

        def _process_vid_stack(action, vid_stack):
            if action.type == ofp.OFPAT_PUSH_VLAN:
                vid_stack.append(ofp.OFPVID_PRESENT)
            elif action.type == ofp.OFPAT_POP_VLAN:
                vid_stack.pop()
            elif action.type == ofp.OFPAT_SET_FIELD:
                if action.key == 'vlan_vid':
                    vid_stack[-1] = action.value
            return vid_stack

        if trace:
            sys.stderr.write(
                'tracing packet flow %s matching to port %s, vid %s\n' % (match, port, vid))

        # vid_stack represents the packet's vlan stack, innermost label listed
        # first
        match_vid = match.get('vlan_vid', 0)
        vid_stack = []
        if match_vid & ofp.OFPVID_PRESENT != 0:
            vid_stack.append(match_vid)
        instructions, _ = self.lookup(match, trace=trace)

        for instruction in instructions:
            if instruction.type != ofp.OFPIT_APPLY_ACTIONS:
                continue
            for action in instruction.actions:
                vid_stack = _process_vid_stack(action, vid_stack)
                if action.type == ofp.OFPAT_OUTPUT:
                    output_result = _output_result(
                        action, vid_stack, port, vid)
                    if output_result is not None:
                        if output_result != full_output:
                            raise FakeOFTableException('Output functions do not match')
                        return output_result
                elif action.type == ofp.OFPAT_GROUP:
                    if action.group_id not in self.groups:
                        raise FakeOFTableException(
                            'output group not in group table: %s' % action)
                    buckets = self.groups[action.group_id].buckets
                    for bucket in buckets:
                        bucket_vid_stack = vid_stack
                        for bucket_action in bucket.actions:
                            bucket_vid_stack = _process_vid_stack(
                                bucket_action, bucket_vid_stack)
                            if bucket_action.type == ofp.OFPAT_OUTPUT:
                                output_result = _output_result(
                                    bucket_action, vid_stack, port, vid)
                                if output_result is not None:
                                    if output_result != full_output:
                                        raise FakeOFTableException('Output functions do not match')
                                    return output_result
        if full_output != False:
            raise FakeOFTableException('Output functions do not match')
        return False

    def apply_instructions_to_packet(self, match):
        """
        Send packet through the fake OF table pipeline
        Args:
            match (dict): A dict keyed by header fields with values, represents
                a packet
        Returns:
            dict: Modified match dict, represents packet that has been through
                the pipeline with values possibly altered
        """
        _, packet_dict = self.lookup(match)
        return packet_dict

    def __str__(self):
        string = ''
        for table_id, table in enumerate(self.tables):
            string += '\n----- Table %u -----\n' % (table_id)
            string += '\n'.join(sorted([str(flowmod) for flowmod in table]))
        return string

    def sort_tables(self):
        """Sort flows in tables by priority order."""
        self.tables = [sorted(table, reverse=True) for table in self.tables]


class FlowMod:
    """Represents a flow modification message and its corresponding entry in
    the flow table.
    """
    MAC_MATCH_FIELDS = (
        'eth_src', 'eth_dst', 'arp_sha', 'arp_tha', 'ipv6_nd_sll',
        'ipv6_nd_tll'
        )
    IPV4_MATCH_FIELDS = ('ipv4_src', 'ipv4_dst', 'arp_spa', 'arp_tpa')
    IPV6_MATCH_FIELDS = ('ipv6_src', 'ipv6_dst', 'ipv6_nd_target')
    HEX_FIELDS = ('eth_type')

    def __init__(self, flowmod):
        """flowmod is a ryu flow modification message object"""
        self.priority = flowmod.priority
        self.cookie = flowmod.cookie
        self.instructions = flowmod.instructions
        self.validate_instructions()
        self.match_values = {}
        self.match_masks = {}
        self.out_port = None
        # flowmod can be an OFPFlowMod or an OFPStats
        if isinstance(flowmod, parser.OFPFlowMod):
            if flowmod.command in (ofp.OFPFC_DELETE, ofp.OFPFC_DELETE_STRICT)\
                    and flowmod.out_port != ofp.OFPP_ANY:
                self.out_port = flowmod.out_port

        for key, val in flowmod.match.items():
            if isinstance(val, tuple):
                val, mask = val
            else:
                mask = -1

            mask = self.match_to_bits(key, mask)
            val = self.match_to_bits(key, val) & mask
            self.match_values[key] = val
            self.match_masks[key] = mask

    def validate_instructions(self):
        instruction_types = set()
        for instruction in self.instructions:
            if instruction.type in instruction_types:
                raise FakeOFTableException(
                    'FlowMod with Multiple instructions of the '
                    'same type: {}'.format(self.instructions))
            instruction_types.add(instruction.type)

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

        # TODO: add cookie and out_group
        for key, val in self.match_values.items():
            if key not in pkt_dict:
                return False
            val_bits = self.match_to_bits(key, pkt_dict[key])
            if val_bits != (val & self.match_masks[key]):
                return False
        return True

    def _matches_match(self, other):
        return (self.priority == other.priority and
                self.match_values == other.match_values and
                self.match_masks == other.match_masks)

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
            return self._matches_match(other)
        for key, val in self.match_values.items():
            if key not in other.match_values:
                return False
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
        for key, val in self.match_values.items():
            if key in other.match_values:
                if val & other.match_masks[key] != other.match_values[key]:
                    return False
                if other.match_values[key] & self.match_masks[key] != val:
                    return False
        return True

    def match_to_bits(self, key, val):
        """convert match fields and masks to bits objects.

        this allows for masked matching. Converting all match fields to the
        same object simplifies things (eg __str__).
        """
        if isinstance(val, Bits):
            return val

        def _val_to_bits(conv, val, length):
            if val == -1:
                return Bits(int=-1, length=length)
            return Bits(bytes=conv(val), length=length)

        if key in self.MAC_MATCH_FIELDS:
            return _val_to_bits(addrconv.mac.text_to_bin, val, 48)
        if key in self.IPV4_MATCH_FIELDS:
            return _val_to_bits(addrconv.ipv4.text_to_bin, val, 32)
        if key in self.IPV6_MATCH_FIELDS:
            return _val_to_bits(addrconv.ipv6.text_to_bin, val, 128)
        return Bits(int=int(val), length=64)

    def bits_to_str(self, key, val):
        if key in self.MAC_MATCH_FIELDS:
            result = addrconv.mac.bin_to_text(val.tobytes())
        elif key in self.IPV4_MATCH_FIELDS:
            result = addrconv.ipv4.bin_to_text(val.tobytes())
        elif key in self.IPV6_MATCH_FIELDS:
            result = addrconv.ipv6.bin_to_text(val.tobytes())
        elif key in self.HEX_FIELDS:
            result = str(val.hex.lstrip('0'))
        else:
            result = str(val.int)
        return result

    def __lt__(self, other):
        return self.priority < other.priority

    def __eq__(self, other):
        return (self._matches_match(other) and
                self.out_port == other.out_port and
                self.instructions == other.instructions)

    def _pretty_field_str(self, key, value, mask=None):
        mask_str = ""
        value_int = value
        mask_int = mask
        if isinstance(value, Bits):
            value_int = value.int
        if isinstance(mask, Bits):
            mask_int = mask.int  # pytype: disable=attribute-error
        elif mask is None:
            mask_int = -1
        if key == 'vlan_vid':
            if value_int & ofp.OFPVID_PRESENT == 0:
                result = 'vlan untagged'
            elif key == 'vlan_vid' and mask_int == ofp.OFPVID_PRESENT:
                result = 'vlan tagged'
            else:
                result = str(value_int ^ ofp.OFPVID_PRESENT)
                if mask_int != -1:
                    mask_str = str(mask_int ^ ofp.OFPVID_PRESENT)
        elif isinstance(value, Bits):
            result = self.bits_to_str(key, value)
            if mask is not None and mask_int != -1:
                mask_str = self.bits_to_str(key, mask)
        elif isinstance(value, str):
            result = value
            if mask is not None:
                mask_str = mask
        elif isinstance(value, int):
            if key in self.HEX_FIELDS:
                result = hex(value)
                if mask is not None and mask != -1:
                    mask_str = hex(mask)
            else:
                result = str(value)
                if mask is not None and mask != -1:
                    mask_str = str(mask)
        if mask_str:
            result += "/{}".format(mask_str)
        return result

    def _pretty_action_str(self, action):
        actions_names_attrs = {
            parser.OFPActionPushVlan.__name__: ('push_vlan', 'ethertype'),
            parser.OFPActionPopVlan.__name__: ('pop_vlan', None),
            parser.OFPActionGroup.__name__: ('group', 'group_id'),
            parser.OFPActionDecNwTtl.__name__: ('dec_nw_ttl', None)}
        value = None
        if isinstance(action, parser.OFPActionOutput):
            name = 'output'
            if action.port == CONTROLLER_PORT:
                value = 'CONTROLLER'
            elif action.port == IN_PORT:
                value = 'IN_PORT'
            else:
                value = str(action.port)
        elif isinstance(action, parser.OFPActionSetField):
            name = 'set_{}'.format(action.key)
            value = self._pretty_field_str(action.key, action.value)
        else:
            name, attr = actions_names_attrs[type(action).__name__]
            if attr:
                value = getattr(action, attr)
        result = name
        if value:
            result += " {}".format(value)
        return result

    def __str__(self):
        result = 'Priority: {0} | Match: '.format(self.priority)

        for key in sorted(self.match_values.keys()):
            val = self.match_values[key]
            mask = self.match_masks[key]
            result += " {} {},".format(
                key, self._pretty_field_str(key, val, mask))
        result = result.rstrip(',')
        result += " | Instructions :"
        if not self.instructions:
            result += ' drop'
        for instruction in self.instructions:
            if isinstance(instruction, parser.OFPInstructionGotoTable):
                result += ' goto {}'.format(instruction.table_id)
            elif isinstance(instruction, parser.OFPInstructionActions):
                for action in instruction.actions:
                    result += " {},".format(self._pretty_action_str(action))
            else:
                result += str(instruction)
        result = result.rstrip(',')
        return result

    def __repr__(self):
        string = 'priority: {0} cookie: {1}'.format(self.priority, self.cookie)
        for key in sorted(self.match_values.keys()):
            mask = self.match_masks[key]
            string += ' {0}: {1}'.format(key, self.match_values[key])
            if mask.int != -1:  # pytype: disable=attribute-error
                string += '/{0}'.format(mask)
        string += ' Instructions: {0}'.format(str(self.instructions))
        return string


class FakeRyuDp:  # pylint: disable=too-few-public-methods
    """Fake ryu Datapath object.

    Just needed to provide a parser to allow us to extract ryu objects from
    JSON
    """

    def __init__(self):
        """Create fake ryu DP"""
        self.ofproto_parser = parser


def parse_print_args():
    """Parse arguments for the print command"""
    arg_parser = argparse.ArgumentParser(
        prog='fakeoftable',
        description='Prints a JSON flow table in a human readable format',
        usage="""
    Print a flow table in a human readable format
    {argv0} print -f FILE
""".format(argv0=sys.argv[0])
        )
    arg_parser.add_argument(
        '-f',
        '--file',
        help='file containing an OFPFlowStatsReply message in JSON format'
        )
    args = arg_parser.parse_args(sys.argv[2:])
    return {'filename': args.file}


def parse_probe_args():
    """Parse arguments for the probe command"""
    arg_parser = argparse.ArgumentParser(
        prog='fakeoftable',
        description='Performs a packet lookup on a JSON openflow table',
        usage="""
    Find the flow table entries in a given flow table that match a given packet
    {argv0} probe -f FILE -p PACKET_STRING
""".format(argv0=sys.argv[0])
        )
    arg_parser.add_argument(
        '-p',
        '--packet',
        metavar='PACKET_STRING',
        help=(
            '''string representation of a packet dictionary eg. '''
            '''"{'in_port': 1, 'eth_dst': '01:80:c2:00:00:02', 'eth_type': '''
            '''34825}"''')
        )
    arg_parser.add_argument(
        '-f',
        '--file',
        metavar='FILE',
        help='file containing an OFPFlowStatsReply message in JSON format'
        )
    args = arg_parser.parse_args(sys.argv[2:])
    packet = args.packet
    packet = ast.literal_eval(args.packet)
    # fix vlan vid
    if 'vlan_vid' in packet:
        packet['vlan_vid'] |= ofp.OFPVID_PRESENT
    return {'packet': packet, 'filename': args.file}


def parse_args():
    """parse arguments"""
    arg_parser = argparse.ArgumentParser(
        prog='fakeoftable',
        description='Performs operations on JSON openflow tables',
        usage="""
    {argv0} <command> <args>

""".format(argv0=sys.argv[0])
        )
    arg_parser.add_argument(
        'command',
        help='Subcommand, either "print" or "probe"'
        )
    args = arg_parser.parse_args(sys.argv[1:2])
    try:
        if args.command == 'probe':
            command_args = parse_probe_args()
        elif args.command == 'print':
            command_args = parse_print_args()
    except (KeyError, IndexError, ValueError, AttributeError) as err:
        print(err)
        arg_parser.print_help()
        sys.exit(-1)
    return (args.command, command_args)


def _print(filename):
    """Prints the JSON flow table from a file in a human readable format"""
    with open(filename, 'r') as f:
        msg = json.load(f)
    dp = FakeRyuDp()
    ofmsg = ofp_parser.ofp_msg_from_jsondict(dp, msg)
    table = FakeOFTable(1)
    table.apply_ofmsgs([ofmsg])
    print(table)


def probe(filename, packet):
    """Prints the actions applied to packet by the table from the file"""
    with open(filename, 'r') as f:
        msg = json.load(f)
    dp = FakeRyuDp()
    ofmsg = ofp_parser.ofp_msg_from_jsondict(dp, msg)
    table = FakeOFTable(1)
    table.apply_ofmsgs([ofmsg])
    instructions, out_packet = table.lookup(packet)
    print(packet)
    for instruction in instructions:
        print(instruction)
    print(out_packet)


def main():
    command, kwargs = parse_args()
    if command == 'probe':
        probe(**kwargs)
    elif command == 'print':
        _print(**kwargs)


if __name__ == '__main__':
    main()
