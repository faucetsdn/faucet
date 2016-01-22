# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2015 Brad Cowie, Christopher Lorier and Joe Stringer.
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

import logging

from util import mac_addr_is_unicast

from ryu.ofproto import ether
from ryu.ofproto import ofproto_v1_3 as ofp
from ryu.ofproto import ofproto_v1_3_parser as parser

def valve_factory(dp):
    """Return a Valve object based dp's hardware configuration field.

    Different datapath hardware has different requirements for the valve
    implementation.

    Currently implemented is the OVSStatelessValve suitable for use with
    "Open vSwitch" and "Allied-Telesis"

    Arguments:
    dp -- a DP object with the configuration for this valve.
    """
    if dp.hardware == 'Open vSwitch'\
    or dp.hardware == 'Allied-Telesis':
        return OVSStatelessValve(dp)
    else:
        return None

class Valve(object):
    """Generates the messages to configure a datapath as a l2 learning switch.

    This is a non functional generic base class. The implementation of datapath
    entry/exit, port entry/exit and packet in messages are hardware dependant
    and therefore are unimplemented.
    """

    def __init__(self, *args, **kwargs):
        raise NotImplementedError

    def reload_config(self, new_dp):
        """Reload the config from new_dp

        KW Arguments:
        new_dp -- A new DP object containing the updated config."""
        raise NotImplementedError

    def datapath_connect(self, dp_id, ports):
        """Generate the default openflow msgs for a datapath upon connection.

        Depending on the implementation, a network state database may be
        updated.

        Arguments:
        dp_id -- the Datapath unique ID (64bit int)
        ports -- a list containing the port numbers of each port on the
            datapath.

        Returns:
        A list of flow mod messages that will be sent in order to the datapath
        in order to configure it."""

        raise NotImplementedError

    def datapath_disconnect(self, dp_id):
        """Update n/w state db upon disconnection of datapath with id dp_id."""
        raise NotImplementedError

    def port_add(self, dp_id, port_num):
        """Generate openflow msgs to update the datapath upon addition of port.

        Arguments:
        dp_id -- the unique id of the datapath
        port_num -- the port number of the new port

        Returns
        A list of flow mod messages to be sent to the datapath."""
        raise NotImplementedError

    def port_delete(self, dp_id, port_num):
        """Generate openflow msgs to update the datapath upon deletion of port.

        Returns
        A list of flow mod messages to be sent to the datapath."""
        raise NotImplementedError

    def rcv_packet(self, dp_id, in_port, vlan_vid, eth_src, eth_dst):
        """Generate openflow msgs to update datapath upon receipt of packet.

        This involves asssociating the ethernet source address of the packet
        with the given in_port (ethernet switching) ideally so that no packets
        from this address are sent to the controller, and packets to this
        address are output to in_port. This may not be fully possible depending
        on the limitations of the datapath.

        Depending on implementation this may involve updating a nw state db.

        Arguments:
        dp_id -- the unique id of the datapath that received the packet (64bit
            int)
        in_port -- the port number of the port that received the packet
        vlan_vid -- the vlan_vid tagged to the packet.
        eth_src -- the ethernet source address of the packet.

        Returns
        A list of flow mod messages to be sent to the datpath."""

        raise NotImplementedError


class OVSStatelessValve(Valve):
    """Valve implementation for Open vSwitch.

    Stateless because the controller does not keep track of the mac addresses,
    it just installs the necessary rules directly to the switch with
    timeouts."""

    def __init__(self, dp, logname='faucet', *args, **kwargs):
        self.dp = dp
        self.logger = logging.getLogger(logname)

    def ignore_port(self, port_num):
        """Ignore non-physical ports."""
        # port numbers > 0xF0000000 indicate a logical port
        return port_num > 0xF0000000

    def ignore_dpid(self, dp_id):
        """Ignore all DPIDs except the DPID configured."""
        if dp_id != self.dp.dp_id:
            self.logger.error("Unknown dpid:%s", dp_id)
            return True
        return False

    def valve_flowmod(self, table_id, match, priority=0,
                     inst=[], command=ofp.OFPFC_ADD, out_port=0,
                     out_group=0, hard_timeout=0, idle_timeout=0):
        """Helper function to construct a flow mod message with cookie."""
        return parser.OFPFlowMod(
            datapath=None,
            cookie=self.dp.cookie,
            command=command,
            table_id=table_id,
            priority=priority,
            out_port=out_port,
            out_group=out_group,
            match=match,
            instructions=inst,
            hard_timeout=hard_timeout,
            idle_timeout=idle_timeout)

    def valve_flowdel(self, table_id, match, priority=0, out_port=ofp.OFPP_ANY):
        """Delete matching flows from a table."""
        return self.valve_flowmod(
            table_id,
            match,
            priority=priority,
            command=ofp.OFPFC_DELETE,
            out_port=out_port,
            out_group=ofp.OFPG_ANY)

    def valve_flowdrop(self, table_id, match, priority=0):
        """Add drop matching flow to a table."""
        return self.valve_flowmod(
            table_id,
            match,
            priority=priority,
            inst=[])

    def delete_all_valve_flows(self):
        """Delete all flows from Valve's tables."""
        ofmsgs = []
        match_all = parser.OFPMatch()
        table_ids = (
            self.dp.vlan_table,
            self.dp.eth_src_table,
            self.dp.eth_dst_table,
            self.dp.flood_table)
        for table_id in table_ids:
            ofmsgs.append(self.valve_flowdel(table_id, match_all))
        return ofmsgs

    def add_default_drop_flows(self):
        """Add default drop rules."""
        ofmsgs = []

        # drop STDP BPDU
        for bpdu_mac in ("01:80:C2:00:00:00", "01:00:0C:CC:CC:CD"):
            match_stp_bpdu = parser.OFPMatch(eth_dst=bpdu_mac)
            ofmsgs.append(self.valve_flowdrop(
                self.dp.vlan_table,
                match_stp_bpdu,
                priority=self.dp.highest_priority))

        # drop LLDP
        match_lldp = parser.OFPMatch(eth_type=ether.ETH_TYPE_LLDP)
        ofmsgs.append(self.valve_flowdrop(
            self.dp.vlan_table,
            match_lldp,
            priority=self.dp.highest_priority))

        # drop on vlan_table miss
        match_all = parser.OFPMatch()
        ofmsgs.append(self.valve_flowdrop(
            self.dp.vlan_table,
            match_all,
            priority=self.dp.lowest_priority))

        return ofmsgs

    def add_vlan_flood_flow(self):
        """Add a flow to flood packets for unknown destinations."""
        match_all = parser.OFPMatch()
        goto_flood_instruction = parser.OFPInstructionGotoTable(
            self.dp.flood_table)
        return [self.valve_flowmod(
            self.dp.eth_dst_table,
            match_all,
            priority=self.dp.lowest_priority,
            inst=[goto_flood_instruction])]

    def add_controller_learn_flow(self):
        """Add a flow to allow the controller to learn and add flows for destinations."""
        match_all = parser.OFPMatch()
        controller_act = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER)]
        controller_inst = parser.OFPInstructionActions(
            ofp.OFPIT_APPLY_ACTIONS, controller_act)
        goto_dst_inst = parser.OFPInstructionGotoTable(self.dp.eth_dst_table)
        return [self.valve_flowmod(
            self.dp.eth_src_table,
            match_all,
            priority=self.dp.lowest_priority,
            inst=[controller_inst, goto_dst_inst])]

    def add_default_flows(self):
        """Configure datapath with necessary default tables and rules."""
        ofmsgs = []
        ofmsgs.extend(self.delete_all_valve_flows())
        ofmsgs.extend(self.add_default_drop_flows())
        ofmsgs.extend(self.add_vlan_flood_flow())
        ofmsgs.extend(self.add_controller_learn_flow())
        return ofmsgs

    def add_ports_and_vlans(self, discovered_port_nums):
        """Add all ports and VLANs from configuration and discovered from switch."""
        ofmsgs = []

        for port_num in discovered_port_nums:
            if self.ignore_port(port_num):
                continue
            if port_num not in self.dp.ports:
                self.logger.info(
                    "Autoconfiguring port:%u based on default config", port_num)
                self.dp.add_port(port_num)

        # all vlan actions
        all_port_nums = set()
        for vlan in self.dp.vlans.itervalues():
            self.logger.info("Configuring VLAN %s", vlan)
            vlan_ports = vlan.tagged + vlan.untagged
            for port in vlan_ports:
                all_port_nums.add(port.number)
            # install eth_dst_table flood ofmsgs
            ofmsgs.append(self.build_flood_rule(vlan))

        # add mirror ports.
        for port_num in self.dp.mirror_from_port.itervalues():
            all_port_nums.add(port_num)

        # now configure all ports
        for port_num in all_port_nums:
            ofmsgs.extend(self.port_add(self.dp.dp_id, port_num))

        return ofmsgs

    def build_flood_rule(self, vlan, modify=False):
        """Add a flow to flood packets to unknown destinations on a VLAN."""
        command = ofp.OFPFC_ADD
        if modify:
            command = ofp.OFPFC_MODIFY_STRICT
        match_vlan = parser.OFPMatch(vlan_vid=vlan.vid|ofp.OFPVID_PRESENT)
        act = []
        for port in vlan.tagged:
            if port.running():
                act.append(parser.OFPActionOutput(port.number))
        act.append(parser.OFPActionPopVlan())
        for port in vlan.untagged:
            if port.running():
                act.append(parser.OFPActionOutput(port.number))
        instructions = [
            parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, act)]
        return self.valve_flowmod(
            self.dp.flood_table,
            match_vlan,
            priority=self.dp.lowest_priority,
            command=command,
            inst=instructions)

    def datapath_connect(self, dp_id, discovered_port_nums):
        if self.ignore_dpid(dp_id):
            return []

        self.logger.info("Configuring datapath")
        ofmsgs = []
        ofmsgs.extend(self.add_default_flows())
        ofmsgs.extend(self.add_ports_and_vlans(discovered_port_nums))
        self.dp.running = True
        return ofmsgs

    def datapath_disconnect(self, dp_id):
        if not self.ignore_dpid(dp_id):
            self.logger.critical("Datapath disconnected")
        return []

    def datapath_down(self, dp_id):
        if self.ignore_dpid(dp_id):
            return []
        self.dp.running = False
        self.logger.warning("Datapath down {0}".format(dp_id))

    def port_add(self, dp_id, port_num):
        if self.ignore_dpid(dp_id) or self.ignore_port(port_num):
            return []

        if port_num not in self.dp.ports:
            # Autoconfigure port
            self.logger.info(
                "Autoconfiguring port:%u based on default config", port_num)
            self.dp.add_port(port_num)

        port = self.dp.ports[port_num]
        self.logger.info("Port added {0}".format(port))
        port.phys_up = True
        in_port_match = parser.OFPMatch(in_port=port_num)
        ofmsgs = []

        if port.running():
            self.logger.info("Sending config for port {0}".format(port))

            # delete eth_src_table rules
            ofmsgs.append(self.valve_flowdel(
                self.dp.eth_src_table,
                in_port_match))

            if port_num in self.dp.mirror_from_port.values():
                # drop all packets from the mirror port
                ofmsgs.append(self.valve_flowdrop(
                    self.dp.vlan_table,
                    in_port_match,
                    priority=self.dp.lowest_priority))
            else:
                mirror_act = []
                mirror_inst = []
                if port_num in self.dp.mirror_from_port:
                    mirror_port_num = self.dp.mirror_from_port[port_num]
                    mirror_act = [parser.OFPActionOutput(mirror_port_num)]
                    mirror_inst = [parser.OFPInstructionActions(
                        ofp.OFPIT_APPLY_ACTIONS, mirror_act)]

                for vid, vlan in self.dp.vlans.iteritems():
                    if port in vlan.untagged:
                        push_vlan_act = mirror_act + [
                            parser.OFPActionPushVlan(ether.ETH_TYPE_8021Q),
                            parser.OFPActionSetField(
                                vlan_vid=vid|ofp.OFPVID_PRESENT)]
                        push_vlan_inst = [
                            parser.OFPInstructionActions(
                                ofp.OFPIT_APPLY_ACTIONS, push_vlan_act),
                            parser.OFPInstructionGotoTable(
                                self.dp.eth_src_table)]
                        ofmsgs.append(self.valve_flowmod(
                            self.dp.vlan_table,
                            in_port_match,
                            priority=self.dp.low_priority,
                            inst=push_vlan_inst))
                        ofmsgs.append(self.build_flood_rule(vlan))
                    elif port in vlan.tagged:
                        vlan_in_port_match = parser.OFPMatch(
                            in_port=port.number,
                            vlan_vid=vid|ofp.OFPVID_PRESENT)
                        vlan_inst = mirror_inst + [
                            parser.OFPInstructionGotoTable(
                                self.dp.eth_src_table)]
                        ofmsgs.append(self.valve_flowmod(
                            self.dp.vlan_table,
                            vlan_in_port_match,
                            priority=self.dp.low_priority,
                            inst=vlan_inst))
                        ofmsgs.append(self.build_flood_rule(vlan))
        return ofmsgs

    def port_delete(self, dp_id, port_num):
        if self.ignore_dpid(dp_id) or self.ignore_port(port_num):
            return []

        if port_num not in self.dp.ports:
            return []

        port = self.dp.ports[port_num]
        port.phys_up = False

        self.logger.warning("Port down: {0}".format(port))

        ofmsgs = []

        # delete vlan_table rules
        vlan_table_match = parser.OFPMatch(in_port=port_num)
        ofmsgs.append(self.valve_flowdel(
            self.dp.vlan_table,
            vlan_table_match,
            priority=self.dp.low_priority))

        # delete eth_dst rules
        match_all = parser.OFPMatch()
        ofmsgs.append(self.valve_flowdel(
            self.dp.eth_dst_table,
            match_all,
            out_port=port_num))

        ofmsgs.append(parser.OFPBarrierRequest(None))

        for vlan in self.dp.vlans.values():
            if port_num in vlan.tagged or port_num in vlan.untagged:
                ofmsgs.append(self.build_flood_rule(vlan), modify=True)

        return ofmsgs

    def rcv_packet(self, dp_id, in_port, vlan_vid, eth_src, eth_dst):
        if self.ignore_dpid(dp_id) or self.ignore_port(in_port):
            return []

        if not self.dp.running:
            self.logger.error("Packet_in on unconfigured datapath")
            return []

        if in_port not in self.dp.ports:
            return []

        if not mac_addr_is_unicast(eth_src):
            self.logger.info(
                "Packet_in with multicast ethernet source address")
            return []

        self.logger.debug("Packet_in dp_id: %x src:%s in_port:%d vid:%s",
                         dp_id, eth_src, in_port, vlan_vid)

        tagged = self.dp.vlans[vlan_vid].port_is_tagged(in_port)

        # flow_mods to be installed
        ofmsgs = []

        # delete any existing ofmsgs for this vlan/mac combination on the
        # src mac table
        src_delete_match = parser.OFPMatch(
            eth_src=eth_src,
            vlan_vid=vlan_vid|ofp.OFPVID_PRESENT)
        ofmsgs.append(self.valve_flowdel(
            self.dp.eth_src_table,
            src_delete_match))

        # delete any existing ofmsgs for this vlan/mac combination on the dst
        # mac table
        dst_delete_match = parser.OFPMatch(
            eth_dst=eth_src,
            vlan_vid=vlan_vid|ofp.OFPVID_PRESENT)
        ofmsgs.append(self.valve_flowdel(
            self.dp.eth_dst_table,
            dst_delete_match))

        ofmsgs.append(parser.OFPBarrierRequest(None))

        mirror_acts = []
        if in_port in self.dp.mirror_from_port:
            mirror_port_num = self.dp.mirror_from_port[in_port]
            mirror_acts = [parser.OFPActionOutput(mirror_port_num)]

        # Update datapath to no longer send packets from this mac to controller
        # note the use of hard_timeout here and idle_timeout for the dst table
        # this is to ensure that the source rules will always be deleted before
        # any rules on the dst table. Otherwise if the dst table rule expires
        # but the src table rule is still being hit intermittantly the switch
        # will flood packets to that dst and not realise it needs to relearn
        # the rule
        src_match = parser.OFPMatch(
            in_port=in_port,
            eth_src=eth_src,
            vlan_vid=vlan_vid|ofp.OFPVID_PRESENT)
        instructions = [parser.OFPInstructionGotoTable(self.dp.eth_dst_table)]
        ofmsgs.append(self.valve_flowmod(
            self.dp.eth_src_table,
            src_match,
            priority=self.dp.high_priority,
            inst=instructions,
            hard_timeout=self.dp.timeout))

        # update datapath to output packets to this mac via the associated port
        dst_match = parser.OFPMatch(
            eth_dst=eth_src,
            vlan_vid=vlan_vid|ofp.OFPVID_PRESENT)
        if tagged:
            dst_act = [parser.OFPActionOutput(in_port)]
        else:
            dst_act = [
                parser.OFPActionPopVlan(),
                parser.OFPActionOutput(in_port)]
        if mirror_acts:
            dst_act.extend(mirror_acts)
        instructions = [
            parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, dst_act)]
        ofmsgs.append(self.valve_flowmod(
            self.dp.eth_dst_table,
            dst_match,
            priority=self.dp.high_priority,
            inst=instructions,
            idle_timeout=self.dp.timeout))

        return ofmsgs

    def reload_config(self, new_dp):
        if not self.dp.running:
            return []
        self.dp = new_dp
        return self.datapath_connect(self.dp.dp_id, self.dp.ports.keys())
