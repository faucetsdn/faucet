# Copyright (C) 2015 Research and Innovation Advanced Network New Zealand Ltd.
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

from ryu.ofproto import ofproto_v1_3 as ofp
from ryu.ofproto import ofproto_v1_3_parser as parser

class FakeOFTable():
    """Fake OFTable is a virtual openflow pipeline used for testing openflow controllers.

    The tables are populated using apply_ofmsgs and can be queried with
    is_ouput.
    """

    def __init__(self):
        self.flowmods = []

    def apply_ofmsgs(self, ofmsgs):
        """This is used to update the fake flowtable.

        It currently only deals with flowmods with the OFPC_ADD or OFPC_DELETE
        commands. Adds are added to the table, and deletes search the table
        for matching flow mods and removes them from the table."""
        # TODO: consider that there is no guarantee the switch will process
        # packets in the desired order. Perhaps there should be some kind of
        # reordering approach.

        for ofmsg in ofmsgs:
            if isinstance(ofmsg, parser.OFPFlowMod):
                if ofmsg.command == ofp.OFPFC_ADD:
                    # from the of 1.3 spec:
                    # "If a flow entry with identical match fields and priority
                    # already resides in the requested table, then that entry [...]
                    # must be cleared from the table"
                    for i in self.find_flowmods(ofmsg, strict=True):
                        self.flowmods.pop(i)
                    self.flowmods.append(ofmsg)
                elif ofmsg.command == ofp.OFPFC_DELETE:
                    # find any matching command and remove it from flowmods
                    # have to delete things in reverse order to ensure the indexes
                    # remain accurate
                    for i in sorted(self.find_flowmods(ofmsg), reverse=True):
                        self.flowmods.pop(i)
                elif ofmsg.command == ofp.OFPFC_DELETE_STRICT:
                    # find a matching command and remove it from flowmods
                    for i in self.find_flowmods(ofmsg, strict=True):
                        self.flowmods.pop(i)
                elif ofmsg.command == ofp.OFPFC_MODIFY:
                    # find any matching command and replace its instructions with
                    # those of ofmsg
                    for i in self.find_flowmods(ofmsg):
                        self.flowmods[i].instructions = ofmsg.instructions
                elif ofmsg.command == ofp.OFPFC_MODIFY_STRICT:
                    # find any matching command and replace it with ofmsg
                    for i in self.find_flowmods(ofmsg, strict=True):
                        self.flowmods[i] = ofmsg

    def find_flowmods(self, ofmsg, strict=False):
        """returns a list the index of any flowmods in self.flowmods that matches ofmsg.

        This is used when applying ofmsgs and looking for overlapping flows.

        Note that if strict is True, there will only be one match"""
        result = []
        i = 0
        while i < len(self.flowmods):
            flowmod = self.flowmods[i]
            if ofmsg.table_id != flowmod.table_id:
                i += 1
                continue
            if strict and ofmsg.priority != flowmod.priority:
                i += 1
                continue
            matches = True
            for k, v in ofmsg.match.iteritems():
                if k not in flowmod.match:
                    matches = False
                    break
                if flowmod.match[k] != v:
                    matches = False
                    break
            if strict and matches:
                for k, v in flowmod.match.iteritems():
                    if k not in ofmsg.match:
                        matches = False
                        break
                    if ofmsg.match[k] != v:
                        matches = False
                        break
            if matches and ofmsg.out_port != ofp.OFPP_ANY and ofmsg.out_port != 0:
                # find the output action for flowmod
                matches = False
                for instruction in flowmod.instructions:
                    if instruction.type == ofp.OFPIT_APPLY_ACTIONS:
                        for action in instruction.actions:
                            if action.type == ofp.OFPAT_OUTPUT:
                                if action.port == ofmsg.out_port:
                                    matches = True
                                    break
                    if matches == True:
                        break
            if matches:
                result.append(i)
            i += 1
        return result

    def lookup(self, _match):
        """Return the entries from flowmods that matches match.

        Searches each table in the pipeline for the entries that will be
        applied to the packet with fields represented by match.

        Arguments:
        _match: a dictionary keyed by header field names with values.
                header fields not provided in _match must be wildcarded for the
                entry to be considered matching.

        Returns: a list of the flowmods that will be applied to the packet
                represented by match
        """
        match = _match.copy()
        flowmods = []
        table = 0
        goto = True
        while goto:
            goto = False
            # find a matching flowmod
            for flowmod in sorted(self.flowmods,
                                    key=lambda x: x.priority,
                                    reverse=True):
                if flowmod.table_id != table:
                    continue
                matches = True
                for k, v in flowmod.match.iteritems():
                    if k not in match:
                        matches = False
                        break
                    elif k == 'eth_dst' or k == 'eth_src':
                        if match[k].lower() != v.lower():
                            matches = False
                            break
                    elif match[k] != v:
                        matches = False
                        break
                if matches:
                    flowmods.append(flowmod)
                    break
            # if a flowmod is found, make modifications to the match values and
            # determine if another lookup is necessary
            if flowmods:
                for instruction in flowmods[-1].instructions:
                    if instruction.type == ofp.OFPIT_GOTO_TABLE:
                        if table != instruction.table_id:
                            table = instruction.table_id
                            goto = True
                    elif instruction.type == ofp.OFPIT_APPLY_ACTIONS:
                        for action in instruction.actions:
                            if action.type == ofp.OFPAT_SET_FIELD:
                                match[action.key] = action.value
        return flowmods

    def is_output(self, match, port=None, vlan=None):
        """Return true if packets with match fields is output to port with
        correct vlan.

        If port is none it will return true if output to any port (including
        special ports) regardless of vlan tag.

        If vlan is none it will return true if output to specified port
        regardless of vlan.

        To specify the packet should be output without a vlan tag set the
        OFPVID_PRESENT bit in vlan is 0.

        Will raise IndexError if a vlan is specified and the packet is output
        without a vlan tag.

        Arguments:
        Match: a dictionary keyed by header field names with values.
        """
        # vid_stack represents the packet's vlan stack
        if 'vlan_vid' in match:
            vid_stack = [match['vlan_vid']] # innermost label listed first
        else:
            # if a tagged port arrives on an untagged interface, we can
            # ignore the label
            vid_stack = []

        flowmods = self.lookup(match)

        for flowmod in flowmods:
            for instruction in flowmod.instructions:
                if instruction.type == ofp.OFPIT_APPLY_ACTIONS:
                    for action in instruction.actions:

                        if action.type == ofp.OFPAT_PUSH_VLAN:
                            vid_stack.append(ofp.OFPVID_PRESENT)

                        elif action.type == ofp.OFPAT_POP_VLAN\
                        and len(vid_stack) != 0:
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

                                if vlan is None:
                                    return True

                                elif vlan & ofp.OFPVID_PRESENT == 0:
                                    return len(vid_stack) == 0

                                else:
                                    return vlan == vid_stack[-1]

        return False

    def __str__(self):
        string = ""
        for table in (0, 1, 2, 3):
            string += "----- Table {0} -----\n".format(table)
            for flowmod in sorted(  self.flowmods,
                                    key=lambda x: x.priority,
                                    reverse=True):
                if flowmod.table_id != table:
                    continue
                string += flowmod
                string += "\n"
        return string
